/* Shared auth/account API backed by backend/app.py. Load before page scripts that use Auth. */

(function () {
    "use strict";

    const LOGIN = "login.html";
    const HOME = "index.html";
    const API = "/api";

    // The pages consume each result immediately after the request.
    function call(method, path, body) {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open(method, API + path, false);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(body === undefined ? null : JSON.stringify(body));

            let data = {};
            try { data = JSON.parse(xhr.responseText || "{}"); } catch (e) { }

            if (xhr.status >= 500) {
                console.error("Server error (" + xhr.status + "):", data.error || xhr.responseText);
            }

            return { status: xhr.status, data: data };
        } catch (e) {
            return { status: 0, data: { ok: false, error: "network" } };
        }
    }

    let cache = null;

    function refresh() {
        const r = call("GET", "/me");
        cache = r.status === 200 && r.data && r.data.user ? r.data.user : null;
        return cache;
    }

    refresh();

    function normalize(raw) {
        let s = String(raw || "").trim();

        if (s.includes("@")) {
            return s.toLowerCase();
        }

        s = s.replace(/[\s\-().]/g, "");

        if (/^\+63\d{10}$/.test(s)) {
            s = "0" + s.slice(3);
        } else if (/^63\d{10}$/.test(s)) {
            s = "0" + s.slice(2);
        }

        return s;
    }

    const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v);
    const isPhone = (v) => /^\+?\d{7,15}$/.test(v);

    const validId = (raw) => {
        const n = normalize(raw);
        return isEmail(n) || isPhone(n);
    };

    function nameFromId(n) {
        if (!isEmail(n)) {
            return "Patient";
        }

        const words = n
            .split("@")[0]
            .split(/[._\-+0-9]+/)
            .filter(Boolean);

        return (
            words.map((w) => w[0].toUpperCase() + w.slice(1)).join(" ") ||
            "Patient"
        );
    }

    function defaultProfile(n) {
        return {
            name: nameFromId(n),
            email: isEmail(n) ? n : "",
            phone: isEmail(n) ? "" : n,
            code: "+63",
            photo: ""
        };
    }

    function createUser(raw, pw, profile) {
        profile = profile || {};
        const name = String(profile.name || "").trim();

        if (!name || name.length > 200) {
            return { ok: false, error: "invalid_name" };
        }

        const r = call("POST", "/signup", {
            id: raw,
            password: pw,
            profile: { name: name }
        });

        if (r.data && r.data.ok) {
            return { ok: true, id: r.data.id };
        }

        return {
            ok: false,
            error: (r.data && r.data.error) || (r.status === 0 ? "network" : "error")
        };
    }

    function verify(raw, pw) {
        const r = call("POST", "/verify", { id: raw, password: pw });

        if (r.data && r.data.ok) {
            return { ok: true, id: r.data.id };
        }

        return {
            ok: false,
            reason: (r.data && r.data.reason) || (r.status === 0 ? "network" : "bad")
        };
    }

    function current() {
        return cache ? cache.id : null;
    }

    function login(raw) {
        const r = call("POST", "/login", { id: raw });

        if (r.data && r.data.ok) {
            refresh();
        }

        return !!(r.data && r.data.ok);
    }

    function logout() {
        call("POST", "/logout");
        cache = null;
    }

    function profile() {
        return cache
            ? Object.assign({}, defaultProfile(cache.id), cache.profile || {})
            : defaultProfile("");
    }

    function saveProfile(patch) {
        if (!cache) {
            return null;
        }

        const r = call("PUT", "/profile", patch);

        if (r.data && r.data.ok) {
            cache.profile = r.data.profile;
            return r.data.profile;
        }

        return null;
    }

    function checkPassword(pw) {
        if (!cache) {
            return false;
        }

        const r = call("POST", "/password/check", { password: pw });
        return !!(r.data && r.data.ok);
    }

    function setPassword(pw) {
        if (!cache) {
            return false;
        }

        const r = call("PUT", "/password", { password: pw });
        return !!(r.data && r.data.ok);
    }

    function deleteAccount() {
        if (!cache) {
            return;
        }

        const r = call("DELETE", "/account");

        if (r.data && r.data.ok) {
            cache = null;
        }
    }

    function getData(key, fallback) {
        return cache &&
            cache.data &&
            Object.prototype.hasOwnProperty.call(cache.data, key)
            ? cache.data[key]
            : fallback;
    }

    // Returns the saved value on success and null on failure.
    function setData(key, value) {
        if (!cache) {
            return null;
        }

        const r = call("PUT", "/data/" + encodeURIComponent(key), { value: value });

        if (r.data && r.data.ok) {
            cache.data = cache.data || {};
            cache.data[key] = value;
            return value === undefined || value === null ? true : value;
        }

        return null;
    }

    const getAppointments = () => {
        const list = getData("appointments", []);
        return (Array.isArray(list) ? list : []).map((a) =>
            a.status === "Pending" ? Object.assign({}, a, { status: "Confirmed" }) : a
        );
    };

    const saveAppointments = (list) => setData("appointments", list);

    const todayISO = () => {
        const d = new Date();
        return (
            d.getFullYear() + "-" +
            String(d.getMonth() + 1).padStart(2, "0") + "-" +
            String(d.getDate()).padStart(2, "0")
        );
    };

    // Returns the end of the slot, or the end of the appointment date if its time is missing.
    function slotEnd(a) {
        if (!a || !a.date) return null;

        const [y, m, d] = String(a.date).slice(0, 10).split("-").map(Number);
        if (!y || !m || !d) return null;

        const times = String(a.time || "").match(/(\d{1,2}):(\d{2})\s*(AM|PM)/gi);
        let h = 23, min = 59;

        if (times && times.length) {
            const t = times[times.length - 1].match(/(\d{1,2}):(\d{2})\s*(AM|PM)/i);
            h = Number(t[1]) % 12 + (t[3].toUpperCase() === "PM" ? 12 : 0);
            min = Number(t[2]);
        }

        return new Date(y, m - 1, d, h, min);
    }

    function recordState(a) {
        const status = String((a && a.status) || "").toLowerCase();

        if (status === "cancelled") return "Cancelled";
        if (status === "completed") return "Completed";

        const end = slotEnd(a);
        return end && end < new Date() ? "Completed" : "Pending";
    }

    function initials(name) {
        const w = String(name || "").trim().split(/\s+/).filter(Boolean);
        if (!w.length) return "?";
        return ((w[0][0] || "") + (w.length > 1 ? w[w.length - 1][0] : "")).toUpperCase();
    }

    function initSidebar() {
        const $ = (id) => document.getElementById(id);
        const sidebar = $("sidebar");
        const scrim = $("scrim");
        const menuBtn = $("menuBtn");
        const closeBtn = $("closeSidebar");
        const search = $("navSearch");
        const noMatch = $("noMatch");

        if (!sidebar) {
            return { setSidebar: function () { } };
        }

        function setSidebar(open) {
            sidebar.classList.toggle("open", !!open);
            if (scrim) scrim.classList.toggle("open", !!open);
            sidebar.setAttribute("aria-hidden", String(!open));
            if (menuBtn) menuBtn.setAttribute("aria-expanded", String(!!open));

            if (open) {
                if (closeBtn) closeBtn.focus();
            } else if (menuBtn && sidebar.contains(document.activeElement)) {
                menuBtn.focus();
            }
        }

        if (menuBtn) menuBtn.addEventListener("click", () => setSidebar(true));
        if (closeBtn) closeBtn.addEventListener("click", () => setSidebar(false));
        if (scrim) scrim.addEventListener("click", () => setSidebar(false));
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") setSidebar(false);
        });

        function paintAccount() {
            const p = profile();
            const avatar = $("sideAvatar");
            const nameEl = $("sideName");
            const mailEl = $("sideEmail");

            if (nameEl) nameEl.textContent = p.name || "";
            if (mailEl) mailEl.textContent = p.email || p.phone || "";

            if (avatar) {
                avatar.textContent = "";
                if (p.photo) {
                    const img = document.createElement("img");
                    img.src = p.photo;
                    img.alt = "";
                    avatar.appendChild(img);
                } else {
                    avatar.textContent = initials(p.name);
                }
            }
        }
        paintAccount();

        function filterNav() {
            if (!search) return;
            const q = search.value.trim().toLowerCase();
            let shown = 0;

            sidebar.querySelectorAll("#nav a").forEach((a) => {
                const hit = !q || a.textContent.toLowerCase().includes(q);
                a.hidden = !hit;
                if (hit) shown++;
            });

            if (noMatch) noMatch.hidden = shown > 0;
        }
        if (search) search.addEventListener("input", filterNav);
        window.addEventListener("langchange", filterNav);

        const logoutLink = sidebar.querySelector(".logout");
        if (logoutLink) {
            logoutLink.addEventListener("click", () => { logout(); });
        }

        return { setSidebar: setSidebar };
    }

    const Auth = {
        LOGIN: LOGIN,
        HOME: HOME,

        normalize: normalize,
        isEmail: isEmail,
        isPhone: isPhone,
        validId: validId,

        createUser: createUser,
        verify: verify,
        current: current,
        login: login,
        logout: logout,

        profile: profile,
        saveProfile: saveProfile,

        checkPassword: checkPassword,
        setPassword: setPassword,
        deleteAccount: deleteAccount,

        getData: getData,
        setData: setData,

        getAppointments: getAppointments,
        saveAppointments: saveAppointments,
        todayISO: todayISO,
        recordState: recordState,

        initSidebar: initSidebar,
        refresh: refresh
    };

    window.Auth = Auth;

    // Run before page scripts so protected pages redirect before initialization.
    (function enforcePageRules() {
        const html = document.documentElement;

        if (html.hasAttribute("data-requires-login") && !current()) {
            location.replace(LOGIN);
            return;
        }

        if (html.hasAttribute("data-guest-only") && current()) {
            location.replace(HOME);
        }
    })();

})();