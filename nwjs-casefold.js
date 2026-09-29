// Put in front of an RPG Maker MV/MZ game by "Sandbox game": NW.js runs it in
// the game's window before any script of the game's own (package.json's
// "inject_js_start").
//
// The games are made on Windows, where file names ignore case, and plenty ask
// for img/pictures/B.png when the file is b.png. Windows and Wine find it; on
// Linux it is missing, and the game stops on "Failed to load" or shows an
// invisible character. So a URL the game hands to an image, a sound, a video,
// a font, XHR or fetch is looked up in the app folder first, and when it names
// nothing there but does once case is ignored, it is pointed at the file that
// exists. A path that exists as written is passed on untouched, and so is
// anything outside the app folder.
(() => {
    "use strict";
    let fs, path, root;
    try {
        fs = require("fs");
        path = require("path");
        root = nw.__dirname;
    } catch (e) {
        return;  // Node switched off in package.json: nothing to look with
    }
    if (!root || location.protocol !== "chrome-extension:") return;

    // Each folder read once: a game asks for thousands of files from a few
    // dozen folders, which do not change under it. Only the misses consult
    // this, so a file made later and asked for as written is never held up.
    const dirs = new Map();
    function entries(dir) {
        let e = dirs.get(dir);
        if (e === undefined) {
            e = null;
            try {
                const names = fs.readdirSync(dir);
                e = { names: new Set(names), lower: new Map() };
                for (const n of names) {
                    const l = n.toLowerCase();
                    if (!e.lower.has(l)) e.lower.set(l, n);
                }
            } catch (_) {}
            dirs.set(dir, e);
        }
        return e;
    }

    // The path segments as they are on disk, or null when they already are,
    // or when not even case-blind matching finds them.
    function fold(parts) {
        let dir = root, changed = false;
        const out = [];
        for (const p of parts) {
            const e = entries(dir);
            if (!e) return null;
            let n = p;
            if (!e.names.has(p)) {
                n = e.lower.get(p.toLowerCase());
                if (n === undefined) return null;
                changed = true;
            }
            out.push(n);
            dir = path.join(dir, n);
        }
        return changed ? out : null;
    }

    // chrome-extension://<id>/ is the app folder.
    function fix(url) {
        if (typeof url !== "string" && !(url instanceof URL)) return url;
        let u, parts;
        try {
            u = new URL(url, document.baseURI);
            if (u.protocol !== location.protocol || u.host !== location.host) return url;
            parts = u.pathname.split("/").slice(1).map(decodeURIComponent);
            if (fs.existsSync(path.join(root, ...parts))) return url;
        } catch (_) {
            return url;
        }
        const found = fold(parts);
        if (!found) return url;
        u.pathname = "/" + found.map(encodeURIComponent).join("/");
        return u.href;
    }

    // Images and sounds (MV's Html5Audio) and videos, through their src.
    for (const proto of [HTMLImageElement.prototype, HTMLMediaElement.prototype,
                         HTMLSourceElement.prototype]) {
        const d = Object.getOwnPropertyDescriptor(proto, "src");
        Object.defineProperty(proto, "src", { ...d, set(v) { d.set.call(this, fix(v)); } });
    }
    // Data, WebAudio and every encrypted file (.rpgmvp, .png_ ...).
    const open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        return open.call(this, method, fix(url), ...rest);
    };
    // MZ streams its audio with fetch.
    const fetch = window.fetch;
    window.fetch = function (input, init) {
        return fetch.call(window, fix(input), init);
    };
    // MZ's FontManager: new FontFace(name, "url(fonts/...)").
    const FontFace = window.FontFace;
    window.FontFace = class extends FontFace {
        constructor(family, source, ...rest) {
            if (typeof source === "string") {
                source = source.replace(/url\((["']?)([^"')]*)\1\)/g,
                                        (_, q, u) => `url(${q}${fix(u)}${q})`);
            }
            super(family, source, ...rest);
        }
    };
})();
