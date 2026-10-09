//
// NOTE: Animated space focus (Hyprland style slide).
//
// MacOS can only animate between adjacent spaces, so instead we capture an image
// of the current and the target space, cover the display (except for the menubar)
// with an overlay window showing both images on top of the wallpaper, switch space
// instantly underneath it and slide the images across in a single motion.
//
// SLSHWCaptureSpace returns the windows of a space even when it is not visible,
// but does not include the wallpaper, which is rendered by a separate window
// owned by WindowManager. Requires Screen Recording permissions.
//

#define SPACE_ANIMATION_KEYFRAME_COUNT 60
#define SPACE_ANIMATION_PRESENT_DELAY_US 20000
#define SPACE_ANIMATION_FADE_DURATION 0.08

struct space_animation
{
    float direction;
    float duration;
    int easing;
    CGImageRef old_image;
    CGImageRef new_image;
    CGImageRef wallpaper_image;
    NSWindow *window;
    CALayer *strip;
};

static bool g_space_animation_in_progress;

bool space_animation_is_in_progress(void)
{
    return __atomic_load_n(&g_space_animation_in_progress, __ATOMIC_ACQUIRE);
}

static float space_animation_ease(int easing, float t)
{
    switch (easing) {
#define ANIMATION_EASING_TYPE_ENTRY(value) case value##_type: return value(t);
        ANIMATION_EASING_TYPE_LIST
#undef ANIMATION_EASING_TYPE_ENTRY
    }

    return t;
}

static CGImageRef space_animation_first_image(CFArrayRef image_list)
{
    if (!image_list) return NULL;

    CGImageRef image = CFArrayGetCount(image_list) > 0 ? (CGImageRef) CFRetain(CFArrayGetValueAtIndex(image_list, 0)) : NULL;
    CFRelease(image_list);

    return image;
}

static uint32_t space_animation_find_wallpaper_window(CGRect bounds)
{
    uint32_t result = 0;

    CFArrayRef window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, kCGNullWindowID);
    if (!window_list) return 0;

    int window_count = CFArrayGetCount(window_list);
    for (int i = 0; i < window_count; ++i) {
        CFDictionaryRef info = CFArrayGetValueAtIndex(window_list, i);

        CFStringRef owner = CFDictionaryGetValue(info, kCGWindowOwnerName);
        if (!owner || !CFEqual(owner, CFSTR("WindowManager"))) continue;

        CFStringRef name = CFDictionaryGetValue(info, kCGWindowName);
        if (!name || !CFEqual(name, CFSTR("Wallpaper"))) continue;

        CGRect frame = {};
        CFDictionaryRef frame_ref = CFDictionaryGetValue(info, kCGWindowBounds);
        if (!frame_ref || !CGRectMakeWithDictionaryRepresentation(frame_ref, &frame)) continue;
        if (!CGRectEqualToRect(frame, bounds)) continue;

        CFNumberRef wid_ref = CFDictionaryGetValue(info, kCGWindowNumber);
        if (wid_ref) CFNumberGetValue(wid_ref, kCFNumberSInt32Type, &result);
        break;
    }

    CFRelease(window_list);
    return result;
}

static NSScreen *space_animation_find_screen(uint32_t did)
{
    for (NSScreen *screen in [NSScreen screens]) {
        NSNumber *number = [[screen deviceDescription] objectForKey:@"NSScreenNumber"];
        if (number && [number unsignedIntValue] == did) return screen;
    }

    return nil;
}

static CALayer *space_animation_image_layer(CGImageRef image, CGRect crop, CGRect frame, CGFloat scale)
{
    CALayer *layer = [CALayer layer];
    layer.frame = frame;
    layer.contentsScale = scale;
    layer.backgroundColor = image ? NULL : CGColorGetConstantColor(kCGColorBlack);

    if (image) {
        CGImageRef cropped = CGImageCreateWithImageInRect(image, crop);
        if (cropped) {
            layer.contents = (id) cropped;
            CGImageRelease(cropped);
        }
    }

    return layer;
}

void space_animation_destroy(struct space_animation *animation)
{
    //
    // NOTE: AppKit objects must be torn down on the main thread.
    //
    if (animation->window && ![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ space_animation_destroy(animation); });
        return;
    }

    if (animation->window) {
        [animation->window orderOut:nil];
        [animation->window release];
    }

    if (animation->old_image)       CGImageRelease(animation->old_image);
    if (animation->new_image)       CGImageRelease(animation->new_image);
    if (animation->wallpaper_image) CGImageRelease(animation->wallpaper_image);

    free(animation);
    __atomic_store_n(&g_space_animation_in_progress, false, __ATOMIC_RELEASE);
}

struct space_animation *space_animation_create(uint32_t did, uint64_t cur_sid, uint64_t new_sid, float direction, float duration, int easing)
{
    if (duration <= 0.0f) return NULL;
    if (!CGPreflightScreenCaptureAccess()) return NULL;

    bool expected = false;
    if (!__atomic_compare_exchange_n(&g_space_animation_in_progress, &expected, true, false, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return NULL;

    struct space_animation *animation = calloc(1, sizeof(struct space_animation));
    if (!animation) {
        __atomic_store_n(&g_space_animation_in_progress, false, __ATOMIC_RELEASE);
        return NULL;
    }

    animation->direction = direction;
    animation->duration = duration;
    animation->easing = easing;

    CGRect bounds = CGDisplayBounds(did);
    uint32_t wallpaper_wid = space_animation_find_wallpaper_window(bounds);

    //
    // NOTE: Capturing a space takes a few tens of milliseconds, so the three
    // captures are done in parallel to keep the latency down.
    //

    __block CGImageRef old_image = NULL;
    __block CGImageRef new_image = NULL;
    __block CGImageRef wallpaper_image = NULL;

    dispatch_group_t group = dispatch_group_create();
    dispatch_queue_t queue = dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0);
    dispatch_group_async(group, queue, ^{ old_image = space_animation_first_image(SLSHWCaptureSpace(g_connection, cur_sid, 0)); });
    dispatch_group_async(group, queue, ^{ new_image = space_animation_first_image(SLSHWCaptureSpace(g_connection, new_sid, 0)); });
    if (wallpaper_wid) {
        dispatch_group_async(group, queue, ^{
            uint32_t wid = wallpaper_wid;
            wallpaper_image = space_animation_first_image(SLSHWCaptureWindowList(g_connection, &wid, 1, (1 << 11) | (1 << 8)));
        });
    }
    dispatch_group_wait(group, DISPATCH_TIME_FOREVER);
    dispatch_release(group);

    animation->old_image = old_image;
    animation->new_image = new_image;
    animation->wallpaper_image = wallpaper_image;

    if (!animation->old_image || !animation->new_image) {
        debug("%s: failed to capture space images (%p, %p)\n", __FUNCTION__, animation->old_image, animation->new_image);
        space_animation_destroy(animation);
        return NULL;
    }

    __block bool did_present = false;
    dispatch_sync(dispatch_get_main_queue(), ^{ @autoreleasepool {
        NSScreen *screen = space_animation_find_screen(did);
        if (!screen) return;

        NSRect screen_frame = [screen frame];
        CGFloat menubar_height = NSMaxY(screen_frame) - NSMaxY([screen visibleFrame]);
        CGFloat width = screen_frame.size.width;
        CGFloat height = screen_frame.size.height - menubar_height;
        CGFloat scale = (CGFloat) CGImageGetWidth(animation->old_image) / width;
        CGRect crop = CGRectMake(0, menubar_height * scale, width * scale, height * scale);
        CGRect frame = CGRectMake(0, 0, width, height);

        NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(screen_frame.origin.x, screen_frame.origin.y, width, height)
                                                       styleMask:NSWindowStyleMaskBorderless
                                                         backing:NSBackingStoreBuffered
                                                           defer:NO];
        [window setReleasedWhenClosed:NO];
        [window setLevel:CGWindowLevelForKey(kCGUtilityWindowLevelKey)];
        //
        // NOTE: The overlay must not be opaque. Windows covered by an opaque window
        // are considered occluded and many applications stop drawing (or discard
        // their contents), which shows up as a flash when the overlay is removed.
        //
        [window setOpaque:NO];
        [window setBackgroundColor:[NSColor clearColor]];
        [window setAnimationBehavior:NSWindowAnimationBehaviorNone];
        [window setHasShadow:NO];
        [window setIgnoresMouseEvents:YES];
        [window setCollectionBehavior:NSWindowCollectionBehaviorCanJoinAllSpaces |
                                      NSWindowCollectionBehaviorStationary |
                                      NSWindowCollectionBehaviorIgnoresCycle |
                                      NSWindowCollectionBehaviorFullScreenAuxiliary];

        NSView *view = [window contentView];
        [view setWantsLayer:YES];

        [CATransaction begin];
        [CATransaction setDisableActions:YES];

        [view.layer addSublayer:space_animation_image_layer(animation->wallpaper_image, crop, frame, scale)];

        CALayer *strip = [CALayer layer];
        strip.frame = frame;
        [strip addSublayer:space_animation_image_layer(animation->old_image, crop, frame, scale)];
        [strip addSublayer:space_animation_image_layer(animation->new_image, crop, CGRectOffset(frame, animation->direction * width, 0), scale)];
        [view.layer addSublayer:strip];

        [CATransaction commit];

        [window orderFrontRegardless];
        [CATransaction flush];

        animation->window = window;
        animation->strip = strip;
        did_present = true;
    }});

    if (!did_present) {
        space_animation_destroy(animation);
        return NULL;
    }

    //
    // NOTE: Give the WindowServer a frame to put the overlay on screen before
    // the space is switched underneath it.
    //
    usleep(SPACE_ANIMATION_PRESENT_DELAY_US);

    return animation;
}

void space_animation_run(struct space_animation *animation)
{
    dispatch_async(dispatch_get_main_queue(), ^{ @autoreleasepool {
        CALayer *strip = animation->strip;
        CGFloat start = strip.position.x;
        CGFloat distance = -animation->direction * strip.bounds.size.width;

        //
        // NOTE: Sample the configured easing function into keyframes so that the
        // animation itself runs entirely in the render server.
        //
        NSMutableArray *values = [NSMutableArray arrayWithCapacity:SPACE_ANIMATION_KEYFRAME_COUNT + 1];
        NSMutableArray *times  = [NSMutableArray arrayWithCapacity:SPACE_ANIMATION_KEYFRAME_COUNT + 1];
        for (int i = 0; i <= SPACE_ANIMATION_KEYFRAME_COUNT; ++i) {
            float t = (float) i / (float) SPACE_ANIMATION_KEYFRAME_COUNT;
            [values addObject:@(start + distance * space_animation_ease(animation->easing, t))];
            [times addObject:@(t)];
        }

        CAKeyframeAnimation *slide = [CAKeyframeAnimation animationWithKeyPath:@"position.x"];
        slide.values = values;
        slide.keyTimes = times;
        slide.duration = animation->duration;
        slide.calculationMode = kCAAnimationLinear;
        slide.fillMode = kCAFillModeForwards;
        slide.removedOnCompletion = NO;

        //
        // NOTE: The captured image of the target space may be slightly out of date,
        // so fade the overlay out instead of removing it abruptly.
        //
        CALayer *root = [[animation->window contentView] layer];
        CABasicAnimation *fade = [CABasicAnimation animationWithKeyPath:@"opacity"];
        fade.fromValue = @(1.0f);
        fade.toValue = @(0.0f);
        fade.beginTime = animation->duration;
        fade.duration = SPACE_ANIMATION_FADE_DURATION;
        fade.fillMode = kCAFillModeBoth;
        fade.removedOnCompletion = NO;

        CAAnimationGroup *group = [CAAnimationGroup animation];
        group.animations = @[ fade ];
        group.duration = animation->duration + SPACE_ANIMATION_FADE_DURATION;
        group.fillMode = kCAFillModeForwards;
        group.removedOnCompletion = NO;

        [CATransaction begin];
        [CATransaction setCompletionBlock:^{
            space_animation_destroy(animation);
        }];
        [strip addAnimation:slide forKey:@"slide"];
        [root addAnimation:group forKey:@"fade"];
        [CATransaction commit];
    }});
}
