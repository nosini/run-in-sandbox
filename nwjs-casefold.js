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
// the same way, on the module object require("fs") returns, and so are calls
// that change or remove a file that already exists. A call that creates a file
// resolves its parent folders only, never the final name, so a save lands in
// an existing Save or save folder without being renamed.
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

    // Node's fs is one object across reloads, child windows and iframes, while
    // this script runs again in each. Its wrappers and the folder cache they
    // share live on the module, so a later run reuses them instead of wrapping
    // the wrappers. The saved calls are the ones before any wrapper.
    const STATE = Symbol.for("sandbox-game.casefold");
    let state = fs[STATE];
    if (state === undefined) {
        state = { exists: fs.existsSync.bind(fs), readdir: fs.readdirSync.bind(fs),
                  dirs: new Map(), wrapped: false };
        Object.defineProperty(fs, STATE, { value: state });
    }
    // The unwrapped calls: resolving a path must not go through the wrappers,
    // or every miss would fold before the caller's miss is noticed.
    const exists = state.exists;
    const readdir = state.readdir;

    // Each folder read once: a game asks for thousands of files from a few
    // dozen folders, which do not change under it. Only the misses consult
    // this, so a file made later and asked for as written is never held up.
    // A successful write drops its parent folder below.
    const dirs = state.dirs;
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

    // Drop the folders a wrapped call changed from the cache.
    function forgetDirs(drop) {
        for (const dir of drop) dirs.delete(dir);
    }

    // Finish a wrapped call: drop the folders it changed once it has worked,
    // for the sync, callback and promise forms alike.
    function finish(name, original, args, self, drop) {
        const forget = () => forgetDirs(drop);
        const last = args[args.length - 1];
        if (name.endsWith("Sync")) {
            const result = original.apply(self, args);
            forget();
            return result;
        }
        if (typeof last === "function") {
            args[args.length - 1] = function (error, ...rest) {
                if (!error) forget();
                return last.call(this, error, ...rest);
            };
            return original.apply(self, args);
        }
        const result = original.apply(self, args);
        if (result && typeof result.then === "function") {
            return result.then((value) => { forget(); return value; },
                               (error) => { throw error; });
        }
        forget();
        return result;
    }

    // A read call, with its first path argument resolved. Properties of the
    // original stay reachable on the wrapper: realpathSync.native and
    // realpath.native are realpath calls too, so they are wrapped as well.
    function readWrapper(original) {
        const wrapper = function (...args) {
            if (args.length && typeof args[0] === "string") {
                try {
                    args[0] = fixPath(args[0]);
                } catch (_) {}
            }
            return original.apply(this, args);
        };
        Object.assign(wrapper, original);
        if (typeof original.native === "function" && original.native !== original) {
            wrapper.native = readWrapper(original.native);
        }
        return wrapper;
    }

    function wrapRead(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = readWrapper(original);
    }

    function wrapWrite(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            if (typeof args[0] === "string") {
                try {
                    args[0] = fixParent(args[0]);
                    const dir = parentOf(args[0]);
                    if (dir !== null) drop.push(dir);
                } catch (_) {}
            }
            return finish(name, original, args, this, drop);
        };
    }

    // A call on something that already exists: its own name is resolved too,
    // so a file written with another case is changed or removed where it is.
    function wrapExisting(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            if (typeof args[0] === "string") {
                try {
                    args[0] = fixPath(args[0]);
                    const dir = parentOf(args[0]);
                    if (dir !== null) drop.push(dir);
                } catch (_) {}
            }
            return finish(name, original, args, this, drop);
        };
    }

    // A write stream opens its file after returning, so its folder is dropped
    // once the open has created the file and once the stream closes it.
    function wrapWriteStream(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            if (typeof args[0] === "string") {
                try {
                    args[0] = fixParent(args[0]);
                    const dir = parentOf(args[0]);
                    if (dir !== null) drop.push(dir);
                } catch (_) {}
            }
            const stream = original.apply(this, args);
            if (stream && typeof stream.on === "function") {
                const forget = () => forgetDirs(drop);
                stream.on("open", forget);
                stream.on("close", forget);
            }
            return stream;
        };
    }

    // A call with a source and a destination: the source is looked up like a
    // read and the destination like a write. symlink() takes its target as the
    // link's content, so that one is left alone.
    function wrapTwoPath(target, name, options = {}) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        const foldSource = options.foldSource !== false;
        const dropSource = options.dropSource === true;
        target[name] = function (...args) {
            const drop = [];
            if (foldSource && typeof args[0] === "string") {
                try {
                    args[0] = fixPath(args[0]);
                } catch (_) {}
            }
            if (dropSource) {
                const dir = parentOf(args[0]);
                if (dir !== null) drop.push(dir);
            }
            if (typeof args[1] === "string") {
                try {
                    args[1] = fixParent(args[1]);
                    const dir = parentOf(args[1]);
                    if (dir !== null) drop.push(dir);
                } catch (_) {}
            }
            return finish(name, original, args, this, drop);
        };
    }

    // open() may create or only change an existing file. Flags that can create
    // resolve the parent folders so a new file keeps the name the game wrote;
    // the rest resolve the whole path, since the file must already be there.
    const WRITE_FLAGS = fs.constants.O_WRONLY | fs.constants.O_RDWR
                      | fs.constants.O_CREAT | fs.constants.O_TRUNC
                      | fs.constants.O_APPEND;
    function openFlags(flags) {
        if (typeof flags === "string") {
            return { create: /[wax]/.test(flags), write: /[wax+]/.test(flags) };
        }
        const value = Number(flags) || 0;
        return { create: (value & fs.constants.O_CREAT) !== 0,
                 write: (value & WRITE_FLAGS) !== 0 };
    }
    function wrapOpen(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            if (typeof args[0] === "string") {
                try {
                    const flags = openFlags(args[1]);
                    args[0] = flags.create ? fixParent(args[0]) : fixPath(args[0]);
                    if (flags.write) {
                        const dir = parentOf(args[0]);
                        if (dir !== null) drop.push(dir);
                    }
                } catch (_) {}
            }
            return finish(name, original, args, this, drop);
        };
    }

    if (!state.wrapped) {
        // Reads go through the resolver. The callback and promise forms use
        // the same names on the module and on fs.promises, which callers share
        // through the module cache.
        for (const name of ["existsSync", "accessSync", "statSync", "lstatSync",
                            "readFileSync", "readdirSync", "realpathSync", "readlinkSync",
                            "opendirSync", "createReadStream", "watch", "watchFile",
                            "unwatchFile", "exists", "access", "stat", "lstat", "readFile",
                            "readdir", "realpath", "readlink", "opendir"]) {
            wrapRead(fs, name);
            wrapRead(fs.promises, name);
        }
        // open() reads with read-only flags and writes with any other.
        for (const name of ["openSync", "open"]) {
            wrapOpen(fs, name);
        }
        wrapOpen(fs.promises, "open");
        // Writes that create a file resolve their parent folders and drop
        // those from the cache. The final name is left alone, and so are the
        // bytes of everything else.
        for (const name of ["writeFileSync", "writeFile", "appendFileSync", "appendFile",
                            "mkdirSync", "mkdir"]) {
            wrapWrite(fs, name);
            wrapWrite(fs.promises, name);
        }
        wrapWriteStream(fs, "createWriteStream");
        // Calls on an existing file resolve its name as well.
        for (const name of ["unlinkSync", "unlink", "rmSync", "rm",
                            "rmdirSync", "rmdir", "truncateSync", "truncate",
                            "chmodSync", "chmod", "utimesSync", "utimes"]) {
            wrapExisting(fs, name);
            wrapExisting(fs.promises, name);
        }
        // Two paths: the source is read and the destination written. A rename
        // also removes the source entry, and a symlink's target is content.
        for (const name of ["copyFileSync", "copyFile", "cpSync", "cp", "linkSync", "link"]) {
            wrapTwoPath(fs, name);
            wrapTwoPath(fs.promises, name);
        }
        for (const name of ["renameSync", "rename"]) {
            wrapTwoPath(fs, name, { dropSource: true });
            wrapTwoPath(fs.promises, name, { dropSource: true });
        }
        for (const name of ["symlinkSync", "symlink"]) {
            wrapTwoPath(fs, name, { foldSource: false });
            wrapTwoPath(fs.promises, name, { foldSource: false });
        }
        state.wrapped = true;
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
