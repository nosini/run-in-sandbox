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
//
// Plugins read files through Node's fs as well, so its read calls are wrapped
// the same way, on the module object require("fs") returns. Writes resolve
// their parent folders only, never the final name, so a save lands in an
// existing Save or save folder without being renamed.
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
    root = path.resolve(root);
    // The unwrapped calls: resolving a path must not go through the wrappers,
    // or every miss would fold before the caller's miss is noticed.
    const exists = fs.existsSync.bind(fs);
    const readdir = fs.readdirSync.bind(fs);

    // Each folder read once: a game asks for thousands of files from a few
    // dozen folders, which do not change under it. Only the misses consult
    // this, so a file made later and asked for as written is never held up.
    // A successful write drops its parent folder below.
    const dirs = new Map();
    function entries(dir) {
        let e = dirs.get(dir);
        if (e === undefined) {
            e = null;
            try {
                const names = readdir(dir);
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

    // An absolute path inside the app folder, or null for anything else. A
    // relative one is taken from the working directory, or from the app folder
    // when the working directory is somewhere else.
    function insidePath(p) {
        if (typeof p !== "string") return null;
        let full;
        try {
            full = path.resolve(p);
            if (full !== root && !full.startsWith(root + path.sep) && !path.isAbsolute(p)) {
                const under = path.resolve(root, p);
                if (under === root || under.startsWith(root + path.sep)) full = under;
            }
        } catch (_) {
            return null;
        }
        if (full !== root && !full.startsWith(root + path.sep)) return null;
        return full;
    }

    function inside(p) {
        const full = insidePath(p);
        if (full === null) return null;
        return full === root ? [] : path.relative(root, full).split(path.sep);
    }

    // A read path that is missing as written, but names a file or folder once
    // case is ignored. Everything else, including descriptors, Buffers and
    // URLs, is handed back as it was.
    function fixPath(p) {
        const full = insidePath(p);
        if (full === null || full === root) return p;
        try {
            if (exists(full)) return p;
        } catch (_) {
            return p;
        }
        const found = fold(path.relative(root, full).split(path.sep));
        return found ? path.join(root, ...found) : p;
    }

    // For a write, only the folders above the final name are resolved, so the
    // name on disk is exactly what the game asked to write.
    function fixParent(p) {
        const full = insidePath(p);
        if (full === null || full === root) return p;
        const parent = path.dirname(full);
        try {
            if (parent === root || exists(parent)) return p;
        } catch (_) {
            return p;
        }
        const found = fold(path.relative(root, parent).split(path.sep));
        return found ? path.join(root, ...found, path.basename(full)) : p;
    }

    function parentOf(p) {
        const full = insidePath(p);
        return full === null ? null : path.dirname(full);
    }

    // chrome-extension://<id>/ is the app folder.
    function fix(url) {
        if (typeof url !== "string" && !(url instanceof URL)) return url;
        let u, parts;
        try {
            u = new URL(url, document.baseURI);
            if (u.protocol !== location.protocol || u.host !== location.host) return url;
            parts = u.pathname.split("/").slice(1).map(decodeURIComponent);
            if (exists(path.join(root, ...parts))) return url;
        } catch (_) {
            return url;
        }
        const found = fold(parts);
        if (!found) return url;
        u.pathname = "/" + found.map(encodeURIComponent).join("/");
        return u.href;
    }

    function wrapRead(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            if (args.length && typeof args[0] === "string") {
                try {
                    args[0] = fixPath(args[0]);
                } catch (_) {}
            }
            return original.apply(this, args);
        };
    }

    function wrapWrite(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            const paths = name.startsWith("rename") ? 2 : 1;
            for (let i = 0; i < paths && i < args.length; i++) {
                if (typeof args[i] !== "string") continue;
                try {
                    args[i] = fixParent(args[i]);
                    const dir = parentOf(args[i]);
                    if (dir !== null) drop.push(dir);
                } catch (_) {}
            }
            const forget = () => { for (const dir of drop) dirs.delete(dir); };
            const last = args[args.length - 1];
            if (name.endsWith("Sync")) {
                const result = original.apply(this, args);
                forget();
                return result;
            }
            if (typeof last === "function") {
                args[args.length - 1] = function (error, ...rest) {
                    if (!error) forget();
                    return last.call(this, error, ...rest);
                };
                return original.apply(this, args);
            }
            const result = original.apply(this, args);
            if (result && typeof result.then === "function") {
                return result.then((value) => { forget(); return value; },
                                   (error) => { throw error; });
            }
            forget();
            return result;
        };
    }

    // Reads go through the resolver. The callback and promise forms use the
    // same names on the module and on fs.promises, which callers share through
    // the module cache.
    for (const name of ["existsSync", "accessSync", "statSync", "lstatSync",
                        "readFileSync", "openSync", "readdirSync",
                        "exists", "access", "stat", "lstat", "readFile", "open", "readdir"]) {
        wrapRead(fs, name);
        wrapRead(fs.promises, name);
    }
    // Writes resolve their parent folders and drop those from the cache. The
    // final name is left alone, and so are the bytes of everything else.
    for (const name of ["writeFileSync", "writeFile", "mkdirSync", "mkdir",
                        "renameSync", "rename", "unlinkSync", "unlink"]) {
        wrapWrite(fs, name);
        wrapWrite(fs.promises, name);
    }

    // Images and sounds (MV's Html5Audio) and videos, through their src.
    for (const proto of [globalThis.HTMLImageElement, globalThis.HTMLMediaElement,
                         globalThis.HTMLSourceElement]) {
        if (!proto) continue;
        const d = Object.getOwnPropertyDescriptor(proto.prototype, "src");
        if (!d) continue;
        Object.defineProperty(proto.prototype, "src",
                              { ...d, set(v) { d.set.call(this, fix(v)); } });
    }
    // Data, WebAudio and every encrypted file (.rpgmvp, .png_ ...).
    if (globalThis.XMLHttpRequest) {
        const open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function (method, url, ...rest) {
            return open.call(this, method, fix(url), ...rest);
        };
    }
    // MZ streams its audio with fetch.
    if (globalThis.window && typeof window.fetch === "function") {
        const fetch = window.fetch;
        window.fetch = function (input, init) {
            return fetch.call(window, fix(input), init);
        };
    }
    // MZ's FontManager: new FontFace(name, "url(fonts/...)").
    if (globalThis.window && typeof window.FontFace === "function") {
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
    }
})();
