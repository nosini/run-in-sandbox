/* A finite Wayland/EGL client: read back a known colour and await a frame callback.
 * Build with generated xdg-shell protocol code; see media.md. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <EGL/egl.h>
#include <GL/gl.h>
#include <wayland-client.h>
#include <wayland-egl.h>
#include "xdg-shell-client-protocol.h"

static struct wl_compositor *compositor;
static struct xdg_wm_base *shell;
static int configured, presented;
static void ping(void *data, struct xdg_wm_base *base, uint32_t serial) {
    (void)data; xdg_wm_base_pong(base, serial);
}
static const struct xdg_wm_base_listener shell_listener = { .ping = ping };
static void global(void *data, struct wl_registry *registry, uint32_t name,
                   const char *interface, uint32_t version) {
    (void)data; (void)version;
    if (!strcmp(interface, "wl_compositor"))
        compositor = wl_registry_bind(registry, name, &wl_compositor_interface, 1);
    if (!strcmp(interface, "xdg_wm_base")) {
        shell = wl_registry_bind(registry, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(shell, &shell_listener, NULL);
    }
}
static void removed(void *data, struct wl_registry *registry, uint32_t name) {
    (void)data; (void)registry; (void)name;
}
static const struct wl_registry_listener registry_listener = {global, removed};
static void configure(void *data, struct xdg_surface *surface, uint32_t serial) {
    (void)data; xdg_surface_ack_configure(surface, serial); configured = 1;
}
static const struct xdg_surface_listener surface_listener = {configure};
static void frame(void *data, struct wl_callback *callback, uint32_t time) {
    (void)data; (void)time; presented = 1; wl_callback_destroy(callback);
}
static const struct wl_callback_listener frame_listener = {frame};
int main(void) {
    alarm(20);
    struct wl_display *display = wl_display_connect(NULL);
    assert(display);
    struct wl_registry *registry = wl_display_get_registry(display);
    wl_registry_add_listener(registry, &registry_listener, NULL);
    assert(wl_display_roundtrip(display) >= 0 && compositor && shell);
    struct wl_surface *surface = wl_compositor_create_surface(compositor);
    struct xdg_surface *xdg = xdg_wm_base_get_xdg_surface(shell, surface);
    xdg_surface_add_listener(xdg, &surface_listener, NULL);
    struct xdg_toplevel *top = xdg_surface_get_toplevel(xdg);
    xdg_toplevel_set_title(top, "run-in-sandbox managed EGL probe");
    wl_surface_commit(surface);
    while (!configured) assert(wl_display_dispatch(display) >= 0);
    EGLDisplay egl = eglGetDisplay((EGLNativeDisplayType)display);
    EGLint major, minor, count;
    assert(eglInitialize(egl, &major, &minor));
    assert(eglBindAPI(EGL_OPENGL_API));
    const EGLint attributes[] = {EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT, EGL_RED_SIZE, 8, EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8, EGL_NONE};
    EGLConfig config;
    assert(eglChooseConfig(egl, attributes, &config, 1, &count) && count);
    EGLContext context = eglCreateContext(egl, config, EGL_NO_CONTEXT, NULL);
    assert(context != EGL_NO_CONTEXT);
    struct wl_egl_window *window = wl_egl_window_create(surface, 64, 64);
    assert(window);
    EGLSurface target = eglCreateWindowSurface(egl, config, (EGLNativeWindowType)window, NULL);
    assert(target != EGL_NO_SURFACE && eglMakeCurrent(egl, target, target, context));
    glViewport(0, 0, 64, 64);
    glClearColor(0.25f, 0.5f, 0.75f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    unsigned char pixel[4];
    glReadPixels(32, 32, 1, 1, GL_RGBA, GL_UNSIGNED_BYTE, pixel);
    assert(glGetError() == GL_NO_ERROR);
    assert(pixel[0] >= 63 && pixel[0] <= 65 && pixel[1] >= 127 && pixel[1] <= 129
           && pixel[2] >= 190 && pixel[2] <= 192);
    struct wl_callback *callback = wl_surface_frame(surface);
    wl_callback_add_listener(callback, &frame_listener, NULL);
    assert(eglSwapBuffers(egl, target));
    while (!presented) assert(wl_display_dispatch(display) >= 0);
    printf("EGL %d.%d; renderer=%s; pixel=%u,%u,%u; compositor frame callback: PASS\n",
           major, minor, glGetString(GL_RENDERER), pixel[0], pixel[1], pixel[2]);
    eglMakeCurrent(egl, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
    eglDestroySurface(egl, target); eglDestroyContext(egl, context); eglTerminate(egl);
    wl_egl_window_destroy(window); xdg_toplevel_destroy(top); xdg_surface_destroy(xdg);
    wl_surface_destroy(surface); xdg_wm_base_destroy(shell); wl_compositor_destroy(compositor);
    wl_registry_destroy(registry); wl_display_disconnect(display);
    return 0;
}
