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
    let fs, path, url, util, root;
    try {
        fs = require("fs");
        path = require("path");
        url = require("url");
        util = require("util");
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

    // Windows games write paths with backslashes. On the Linux side they are
    // separators too, not characters in a file name.
    function normalize(p) {
        return process.platform === "win32" ? p : p.replace(/\\/g, "/");
    }

    function withinRoot(full) {
        return full === root || full.startsWith(root + path.sep);
    }

    // An fs path argument as a string, with the form it arrived in, or null
    // for what is not a path (a descriptor, an options object). fs takes
    // strings, Buffers of bytes and file: URLs; a resolved path goes back in
    // the same form, so a caller's Buffer stays a Buffer and a URL a URL.
    function pathArg(p) {
        if (typeof p === "string") return { value: p, kind: "string" };
        if (Buffer.isBuffer(p)) return { value: p.toString(), kind: "buffer" };
        if (p instanceof URL) {
            if (p.protocol !== "file:") return null;
            try {
                return { value: url.fileURLToPath(p), kind: "url" };
            } catch (_) {
                return null;
            }
        }
        return null;
    }

    function pathValue(value, kind) {
        if (kind === "buffer") return Buffer.from(value);
        if (kind === "url") return url.pathToFileURL(value);
        return value;
    }

    // An absolute path inside the app folder, or null for anything else. A
    // relative one is taken from the working directory, or from the app folder
    // when nothing exists there under that name.
    function insidePath(p) {
        const arg = pathArg(p);
        if (arg === null) return null;
        p = normalize(arg.value);
        let full;
        try {
            full = path.resolve(p);
            if (!withinRoot(full) && !path.isAbsolute(p)) {
                // A CWD-relative path that exists outside the app stays there.
                try {
                    if (exists(full)) return null;
                } catch (_) {
                    return null;
                }
                full = path.resolve(root, p);
            }
        } catch (_) {
            return null;
        }
        return withinRoot(full) ? full : null;
    }

    function foldChild(dir, name) {
        const e = entries(dir);
        if (!e) return null;
        if (e.names.has(name)) return name;
        const folded = e.lower.get(name.toLowerCase());
        return folded === undefined ? null : folded;
    }

    // The path segments as they are on disk, or null when they already are,
    // or when not even case-blind matching finds them.
    function fold(parts) {
        let dir = root, changed = false;
        const out = [];
        for (const p of parts) {
            const n = foldChild(dir, p);
            if (n === null) return null;
            if (n !== p) changed = true;
            out.push(n);
            dir = path.join(dir, n);
        }
        return changed ? out : null;
    }

    // For a path whose final folders may not exist yet: fold every segment
    // that is there and keep the missing ones as written, so a recursive
    // mkdir below an existing Save still lands in Save.
    function foldPrefix(parts) {
        let dir = root, changed = false, missing = false;
        const out = [];
        for (const p of parts) {
            let n = p;
            if (!missing) {
                n = foldChild(dir, p);
                if (n === null) {
                    missing = true;
                    n = p;
                } else if (n !== p) {
                    changed = true;
                }
            }
            out.push(n);
            dir = path.join(dir, n);
        }
        return changed ? out : null;
    }

    // A read path that is missing as written, but names a file or folder once
    // case is ignored. Everything else, including descriptors, Buffers and
    // URLs, is handed back as it was.
    function fixPath(p) {
        // Within the app, backslashes become "/" first: a path that needs no
        // case folding still goes back naming its file, not "img\pictures".
        // A path elsewhere stays as it was.
        const full = insidePath(p);
        if (full === null || full === root) return p;
        p = normalize(p);
        const cwd = path.resolve(p);
        try {
            if (exists(full)) return full === cwd ? p : full;
        } catch (_) {
            return p;
        }
        const found = fold(path.relative(root, full).split(path.sep));
        if (found) return path.join(root, ...found);
        return full === cwd ? p : full;
    }

    // A write path. Existing folders and an existing file under another case
    // are reused, so a save written as SAVE/OLD.SAV changes Save/old.sav
    // instead of making a second file that readdir may return either way.
    function fixWrite(p) {
        // Within the app, backslashes become "/" first here too, so a save
        // named save\new.sav lands in the save folder, not beside it.
        const full = insidePath(p);
        if (full === null || full === root) return p;
        p = normalize(p);
        const cwd = path.resolve(p);
        const parts = path.relative(root, full).split(path.sep);
        const name = parts.pop();
        const found = foldPrefix(parts);
        const parentParts = found || parts;
        const parent = parentParts.length ? path.join(root, ...parentParts) : root;
        const existing = foldChild(parent, name);
        if (found || existing !== null || full !== cwd) {
            return path.join(parent, existing === null ? name : existing);
        }
        return p;
    }

    // fixPath and fixWrite work on the string form. These take any form fs
    // accepts and hand the result back in the form the caller used, leaving a
    // path that needed no change exactly as it was.
    function fixReadArg(p) {
        const arg = pathArg(p);
        if (arg === null) return p;
        const fixed = fixPath(arg.value);
        return fixed === arg.value ? p : pathValue(fixed, arg.kind);
    }

    function fixWriteArg(p) {
        const arg = pathArg(p);
        if (arg === null) return p;
        const fixed = fixWrite(arg.value);
        return fixed === arg.value ? p : pathValue(fixed, arg.kind);
    }

    // chrome-extension://<id>/ is the app folder.
    function fix(url) {
        if (typeof url !== "string" && !(url instanceof URL)) return url;
        let u, parts;
        try {
            const value = typeof url === "string" ? normalize(url) : url;
            u = new URL(value, document.baseURI);
            if (u.protocol !== location.protocol || u.host !== location.host) return url;
            parts = u.pathname.split("/").slice(1).filter((part) => part !== "");
            parts = parts.map(decodeURIComponent);
            // An encoded slash or dot segment would otherwise become a real
            // separator here, taking the lookup outside the app folder.
            if (parts.some((p) => p === "." || p === ".." || p.includes("/")
                                  || p.includes("\\") || p.includes("\0"))) return url;
            const target = path.join(root, ...parts);
            if (!withinRoot(target)) return url;
            // There as written: handed back untouched when it arrived in
            // URL form already, and rebuilt with "/" when backslashes had
            // to be turned into separators -- a non-special scheme keeps a
            // backslash in the path, which the app cannot load.
            if (exists(target)) return value === url ? url : u.href;
        } catch (_) {
            return url;
        }
        const found = fold(parts);
        if (!found) return url;
        u.pathname = "/" + found.map(encodeURIComponent).join("/");
        return u.href;
    }

    // Drop folders a wrapped call changed from the cache, and every folder
    // below a renamed or removed one.
    function forgetDirs(drop) {
        for (const item of drop) {
            if (typeof item === "string") {
                dirs.delete(item);
            } else if (item.tree) {
                const prefix = item.path.endsWith(path.sep) ? item.path : item.path + path.sep;
                for (const key of Array.from(dirs.keys())) {
                    if (key === item.path || key.startsWith(prefix)) dirs.delete(key);
                }
            } else {
                dirs.delete(item.path);
            }
        }
    }

    // The changed path itself, and every folder above it up to the app root:
    // creating a deep folder also changes the listing of each parent that was
    // cached as missing before it.
    function changedDir(full, tree = true) {
        const drop = [];
        if (full === null || !withinRoot(full)) return drop;
        drop.push({ path: full, tree });
        let dir = path.dirname(full);
        while (withinRoot(dir)) {
            drop.push({ path: dir });
            if (dir === root) break;
            dir = path.dirname(dir);
        }
        return drop;
    }

    // Finish a wrapped call: drop the folders it changed once it has ended,
    // for the sync, callback and promise forms alike. A failed call may
    // still have written or changed a folder, so the folders go however it
    // ended, and the error is the caller's either way.
    function finish(name, original, args, self, drop) {
        const forget = () => forgetDirs(drop);
        const last = args[args.length - 1];
        if (name.endsWith("Sync")) {
            try {
                return original.apply(self, args);
            } finally {
                // A throwing call may still have written or changed a folder.
                forget();
            }
        }
        if (typeof last === "function") {
            // Dropped before the callback runs, so a callback that throws
            // holds nothing back either, and the callback sees the same
            // error it would without this.
            args[args.length - 1] = function (error, ...rest) {
                forget();
                return last.call(this, error, ...rest);
            };
            return original.apply(self, args);
        }
        const result = original.apply(self, args);
        if (result && typeof result.then === "function") {
            return result.then((value) => { forget(); return value; },
                               (error) => { forget(); throw error; });
        }
        forget();
        return result;
    }

    // A read call, with its first path argument resolved. Properties of the
    // original stay reachable on the wrapper: realpathSync.native and
    // realpath.native are realpath calls too, so they are wrapped as well.
    function readWrapper(original) {
        const wrapper = function (...args) {
            if (args.length) {
                try {
                    args[0] = fixReadArg(args[0]);
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
            let full = null;
            if (args.length) {
                try {
                    args[0] = fixWriteArg(args[0]);
                    full = insidePath(args[0]);
                } catch (_) {}
            }
            return finish(name, original, args, this, changedDir(full));
        };
    }

    // A call on something that already exists: its own name is resolved too,
    // so a file written with another case is changed or removed where it is.
    function wrapExisting(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            let full = null;
            if (args.length) {
                try {
                    args[0] = fixReadArg(args[0]);
                    full = insidePath(args[0]);
                } catch (_) {}
            }
            return finish(name, original, args, this, changedDir(full));
        };
    }

    // A write stream opens its file after returning, so its folder is dropped
    // once the open has created the file and once the stream closes it.
    function wrapWriteStream(target, name) {
        const original = target && target[name];
        if (typeof original !== "function") return;
        target[name] = function (...args) {
            const drop = [];
            if (args.length) {
                try {
                    args[0] = fixWriteArg(args[0]);
                    drop.push(...changedDir(insidePath(args[0])));
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
            if (foldSource && args.length) {
                try {
                    args[0] = fixReadArg(args[0]);
                } catch (_) {}
            }
            if (dropSource && args.length) {
                try {
                    drop.push(...changedDir(insidePath(args[0])));
                } catch (_) {}
            }
            if (args.length > 1) {
                try {
                    args[1] = fixWriteArg(args[1]);
                    drop.push(...changedDir(insidePath(args[1])));
                } catch (_) {}
            }
            return finish(name, original, args, this, drop);
        };
    }

    // open() may create or only change an existing file. Flags that can create
    // resolve an existing file under another case and the folders above a new
    // one; the rest resolve the whole path, since it must already be there.
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
            let full = null;
            if (args.length) {
                try {
                    const flags = openFlags(args[1]);
                    args[0] = flags.create ? fixWriteArg(args[0]) : fixReadArg(args[0]);
                    if (flags.write) full = insidePath(args[0]);
                } catch (_) {}
            }
            return finish(name, original, args, this, changedDir(full));
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
        // fs.exists has a [util.promisify.custom] result that resolves to the
        // boolean. Object.assign above copies plain names and enumerable
        // symbols, not that non-enumerable one, so copy it by hand: without it
        // util.promisify(fs.exists) would treat the boolean as an error.
        if (typeof fs.exists === "function") {
            const existsWrapped = fs.exists;
            Object.defineProperty(existsWrapped, util.promisify.custom, {
                value: function (p) {
                    return new Promise((resolve) => existsWrapped(p, resolve));
                },
            });
        }
        state.wrapped = true;
    }

    // A later run on the same page (a reload, another window) must not wrap a
    // wrapper again.
    const WRAPPED = Symbol.for("sandbox-game.casefold.wrapped");
    function mark(fn) {
        try {
            Object.defineProperty(fn, WRAPPED, { value: true });
        } catch (_) {}
        return fn;
    }
    function isWrapped(fn) {
        return typeof fn === "function" && fn[WRAPPED] === true;
    }

    // Images and sounds (MV's Html5Audio) and videos, through their src.
    for (const proto of [globalThis.HTMLImageElement, globalThis.HTMLMediaElement,
                         globalThis.HTMLSourceElement]) {
        if (!proto) continue;
        const d = Object.getOwnPropertyDescriptor(proto.prototype, "src");
        if (!d || typeof d.set !== "function" || isWrapped(d.set)) continue;
        const set = mark(function (v) { d.set.call(this, fix(v)); });
        Object.defineProperty(proto.prototype, "src", { ...d, set });
    }
    // Data, WebAudio and every encrypted file (.rpgmvp, .png_ ...).
    if (globalThis.XMLHttpRequest) {
        const open = XMLHttpRequest.prototype.open;
        if (!isWrapped(open)) {
            XMLHttpRequest.prototype.open = mark(function (method, url, ...rest) {
                return open.call(this, method, fix(url), ...rest);
            });
        }
    }
    // MZ streams its audio with fetch, sometimes with a Request object.
    if (globalThis.window && typeof window.fetch === "function" && !isWrapped(window.fetch)) {
        const fetch = window.fetch;
        const RequestCtor = globalThis.Request || window.Request;
        window.fetch = mark(function (input, init) {
            if (typeof RequestCtor === "function" && input instanceof RequestCtor) {
                const url = fix(input.url);
                if (url !== input.url) {
                    try {
                        input = new RequestCtor(url, input);
                    } catch (_) {}
                }
            } else {
                input = fix(input);
            }
            return fetch.call(window, input, init);
        });
    }
    // new Audio("sounds/Theme.ogg").
    const AudioCtor = globalThis.Audio || (globalThis.window && window.Audio);
    if (typeof AudioCtor === "function" && !isWrapped(AudioCtor)) {
        const Audio = mark(function (...args) {
            if (typeof args[0] === "string") args[0] = fix(args[0]);
            return new AudioCtor(...args);
        });
        Audio.prototype = AudioCtor.prototype;
        globalThis.Audio = Audio;
        if (globalThis.window) window.Audio = Audio;
    }
    // element.setAttribute("src" | "href", ...), which bypasses the property.
    const ElementCtor = globalThis.Element || (globalThis.window && window.Element);
    if (ElementCtor && ElementCtor.prototype
        && typeof ElementCtor.prototype.setAttribute === "function") {
        const setAttribute = ElementCtor.prototype.setAttribute;
        if (!isWrapped(setAttribute)) {
            ElementCtor.prototype.setAttribute = mark(function (name, value, ...rest) {
                const key = String(name).toLowerCase();
                if (typeof value === "string" && (key === "src" || key === "href")) {
                    value = fix(value);
                }
                return setAttribute.call(this, name, value, ...rest);
            });
        }
    }
    // MZ's FontManager: new FontFace(name, "url(fonts/...)").
    if (globalThis.window && typeof window.FontFace === "function"
        && !isWrapped(window.FontFace)) {
        const FontFace = window.FontFace;
        window.FontFace = mark(class extends FontFace {
            constructor(family, source, ...rest) {
                if (typeof source === "string") {
                    source = source.replace(/url\(\s*(?:(["'])([\s\S]*?)\1|([^)]*))\s*\)/g,
                                            (_, q, quoted, bare) => {
                        const value = q ? quoted : bare.trim();
                        return `url(${q || ""}${fix(value)}${q || ""})`;
                    });
                }
                super(family, source, ...rest);
            }
        });
    }
})();
