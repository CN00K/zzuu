//  HIDTouchInjector.mm
//  [zzuu-jb] See header. Implementation adapted from:
//   - TrollVNC STHIDEventGenerator.mm (GPLv2, (c) 82flex & contributors)
//   - zxtouch pccontrol/Touch.xm (senderID discovery fallback)
//   - vncforios hid.m (Ethan Arbuckle)
//  SenderID: hardcode the iOS 14.8-26 value that TrollVNC ships; if events
//  do not land, callers can fall back to sniffing a real touch via the
//  monitor client (see +sniffSenderIDFromRealTouches).

#import "HIDTouchInjector.h"

#import <UIKit/UIKit.h>
#import <mach/mach_time.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <objc/runtime.h>

// ---------- IOKit HID private SPI ----------
typedef mach_port_t IOHIDEventSystemClientRef;
typedef struct __IOHIDEvent *IOHIDEventRef;
typedef CGFloat IOHIDFloat;

// Some SDKs / toolchains used in CI may not expose IOOptionBits.
// Provide a local definition for compatibility (uint32_t historically).
#include <stdint.h>
#ifndef IOOptionBits
typedef uint32_t IOOptionBits;
#endif

enum {
    kIOHIDDigitizerTransducerTypeHand = 3,
    kIOHIDDigitizerTransducerTypeFinger = 2,
};

enum {
    kIOHIDDigitizerEventRange = 1 << 0,
    kIOHIDDigitizerEventTouch = 1 << 1,
    kIOHIDDigitizerEventPosition = 1 << 2,
    kIOHIDDigitizerEventStop = 1 << 3,
    kIOHIDDigitizerEventPeak = 1 << 4,
    kIOHIDDigitizerEventIdentity = 1 << 5,
    kIOHIDDigitizerEventAttribute = 1 << 6,
    kIOHIDDigitizerEventCancel = 1 << 7,
    kIOHIDDigitizerEventStart = 1 << 8,
    kIOHIDDigitizerEventResting = 1 << 9,
    kIOHIDDigitizerEventExpiration = 1 << 10,
    kIOHIDDigitizerEventUpcoming = 1 << 11,
};

enum {
    kIOHIDEventFieldDigitizerX = 0x000B0001,
    kIOHIDEventFieldDigitizerY = 0x000B0002,
    kIOHIDEventFieldDigitizerZTotal = 0x000B0009,
    kIOHIDEventFieldDigitizerButtonMask = 0x000B000A,
    kIOHIDEventFieldDigitizerEventType = 0x000B000B,
    kIOHIDEventFieldDigitizerEventMask = 0x000B000C,
    kIOHIDEventFieldDigitizerRange = 0x000B0016,
    kIOHIDEventFieldDigitizerTouch = 0x000B0017,
    kIOHIDEventFieldDigitizerIsDisplayIntegrated = 0x000B0023,
    kIOHIDEventFieldIsBuiltIn = 0x000B0024,
    kIOHIDEventFieldDigitizerQualityRadiiAccuracy = 0x000B001E,
    kIOHIDEventFieldDigitizerMinorRadius = 0x000B0015,
    kIOHIDEventFieldDigitizerMajorRadius = 0x000B0014,
};

#define kHIDPage_KeyboardOrKeypad 0x07
#define kHIDPage_GenericDesktop   0x01
#define kHIDUsage_GD_Start 0x3A  // Home button (Button 134 -> GD page usage)
#define kHIDUsage_Button_134 0x86

// Dynamically resolved symbols (IOKit framework, private exports).
static void * _Nullable iokitHandle(void) {
    static void *h; static dispatch_once_t once;
    dispatch_once(&once, ^{ h = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_NOW); });
    return h;
}

#define IOHID_SYM(ret, name, sig...) \
    static ret (*name)(sig); \
    if (!name) name = (ret (*)(sig))dlsym(iokitHandle(), #name);

static IOHIDEventRef CreateDigitizerEvent(CFAllocatorRef allocator, UInt64 ts,
        UInt32 transducerType, UInt32 index, UInt32 identity, UInt32 eventMask,
        UInt32 buttonEvent, IOHIDFloat x, IOHIDFloat y, IOHIDFloat z,
        IOHIDFloat tipPressure, IOHIDFloat barrelPressure, Boolean range,
        Boolean touch, IOOptionBits options) {
    IOHID_SYM(IOHIDEventRef, fn, CFAllocatorRef, UInt64, UInt32, UInt32, UInt32,
              UInt32, UInt32, IOHIDFloat, IOHIDFloat, IOHIDFloat, IOHIDFloat,
              IOHIDFloat, Boolean, Boolean, IOOptionBits);
    if (!fn) return NULL;
    return fn(allocator, ts, transducerType, index, identity, eventMask,
              buttonEvent, x, y, z, tipPressure, barrelPressure, range, touch,
              options);
}

static IOHIDEventRef CreateDigitizerFingerEvent(CFAllocatorRef allocator, UInt64 ts,
        UInt32 index, UInt32 identity, UInt32 eventMask, IOHIDFloat x, IOHIDFloat y,
        IOHIDFloat z, IOHIDFloat tipPressure, IOHIDFloat twist, Boolean range,
        Boolean touch, IOOptionBits options) {
    IOHID_SYM(IOHIDEventRef, fn, CFAllocatorRef, UInt64, UInt32, UInt32, UInt32,
              IOHIDFloat, IOHIDFloat, IOHIDFloat, IOHIDFloat, IOHIDFloat,
              Boolean, Boolean, IOOptionBits);
    if (!fn) return NULL;
    return fn(allocator, ts, index, identity, eventMask, x, y, z, tipPressure,
              twist, range, touch, options);
}

static IOHIDEventRef CreateKeyboardEvent(CFAllocatorRef allocator, UInt64 ts,
        UInt32 usagePage, UInt32 usage, Boolean down, IOOptionBits options) {
    IOHID_SYM(IOHIDEventRef, fn, CFAllocatorRef, UInt64, UInt32, UInt32, Boolean,
              IOOptionBits);
    if (!fn) return NULL;
    return fn(allocator, ts, usagePage, usage, down, options);
}

static void SetSenderID(IOHIDEventRef event, uint64_t senderID) {
    IOHID_SYM(void, fn, IOHIDEventRef, uint64_t);
    if (fn) fn(event, senderID);
}

static void AppendEvent(IOHIDEventRef parent, IOHIDEventRef child, IOOptionBits o) {
    IOHID_SYM(void, fn, IOHIDEventRef, IOHIDEventRef, IOOptionBits);
    if (fn) fn(parent, child, o);
}

static void SetIntegerValue(IOHIDEventRef e, UInt32 field, int value) {
    IOHID_SYM(void, fn, IOHIDEventRef, UInt32, int);
    if (fn) fn(e, field, value);
}

static IOHIDEventSystemClientRef CreateSystemClient(void) {
    IOHID_SYM(IOHIDEventSystemClientRef, fn, CFAllocatorRef);
    if (!fn) return MACH_PORT_NULL;
    return fn(kCFAllocatorDefault);
}

static void DispatchEvent(IOHIDEventSystemClientRef client, IOHIDEventRef e) {
    IOHID_SYM(void, fn, IOHIDEventSystemClientRef, IOHIDEventRef);
    if (fn) fn(client, e);
}

// ---------- implementation ----------

static const NSTimeInterval kFingerLiftDelay = 0.05;
static const NSTimeInterval kMultiTapInterval = 0.12;
static const NSTimeInterval kMoveInterval = 0.016;
static const IOHIDFloat kDefaultRadius = 5.0;

// iOS 14.8 - 26 senderID (TrollVNC ships this; works system-wide).
static const uint64_t kSenderIDIOS14to26 = 0x8000000817319371ULL;

static int fingerIds[] = {2, 3, 4, 5, 1, 6, 7, 8, 9};

@interface HIDTouchInjector () {
    IOHIDEventSystemClientRef _client;
    dispatch_queue_t _queue;
}
@end

@implementation HIDTouchInjector

+ (instancetype)shared {
    static HIDTouchInjector *s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[HIDTouchInjector alloc] init]; });
    return s;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _client = CreateSystemClient();
        _queue = dispatch_queue_create("zzuu.hid.inject", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (CGSize)screenSize {
    return [UIScreen mainScreen].bounds.size;
}

- (void)_send:(IOHIDEventRef)event {
    if (!event) return;
    SetSenderID(event, kSenderIDIOS14to26);
    IOHIDEventRef copy = event;
    CFRetain(copy);
    dispatch_async(_queue, ^{
        DispatchEvent(self->_client, copy);
        CFRelease(copy);
    });
}

- (void)_sendSync:(IOHIDEventRef)event {
    if (!event) return;
    SetSenderID(event, kSenderIDIOS14to26);
    dispatch_sync(_queue, ^{ DispatchEvent(_client, event); });
}

#pragma mark - finger event builder

- (IOHIDEventRef)_fingerEvent:(UInt32)fid identity:(UInt32)ident
                     eventMask:(UInt32)mask x:(IOHIDFloat)x y:(IOHIDFloat)y
                     isRange:(BOOL)range isTouch:(BOOL)touch {
    IOHIDEventRef f = CreateDigitizerFingerEvent(
        kCFAllocatorDefault, mach_absolute_time(), fid, ident, mask,
        x, y, 0.0, 0.0, 0.0, range, touch, 0);
    if (f) {
        SetIntegerValue(f, kIOHIDEventFieldDigitizerMajorRadius, 0);
        SetIntegerValue(f, kIOHIDEventFieldDigitizerMinorRadius, 0);
        // zxtouch sets radius via raw field ids 0xb0014/0xb0015 above.
    }
    return f;
}

#pragma mark - tap

- (void)tapAtPoint:(CGPoint)point {
    [self _tap:point count:1];
}

- (void)doubleTapAtPoint:(CGPoint)point {
    [self _tap:point count:2];
}

- (void)_tap:(CGPoint)p count:(NSUInteger)count {
    CGSize s = [self screenSize];
    IOHIDFloat x = p.x, y = p.y;  // points == digitizer space on iOS
    for (NSUInteger i = 0; i < count; i++) {
        // hand "touched"
        IOHIDEventRef hand = CreateDigitizerEvent(
            kCFAllocatorDefault, mach_absolute_time(),
            kIOHIDDigitizerTransducerTypeHand, 0, 1,
            kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity,
            0, x, y, 0, 0, 0, YES, YES, 0);
        SetIntegerValue(hand, kIOHIDEventFieldIsBuiltIn, 1);
        SetIntegerValue(hand, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
        IOHIDEventRef f1 = [self _fingerEvent:2 identity:1
            eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
            x:x y:y isRange:YES isTouch:YES];
        AppendEvent(hand, f1, 0); CFRelease(f1);
        [self _sendSync:hand]; CFRelease(hand);

        // hand "moved" briefly (some apps require a move to register)
        [NSThread sleepForTimeInterval:0.03];

        // hand "lifted"
        UInt32 liftMask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
                        | kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition;
        IOHIDEventRef handUp = CreateDigitizerEvent(
            kCFAllocatorDefault, mach_absolute_time(),
            kIOHIDDigitizerTransducerTypeHand, 0, 1, liftMask,
            0, x, y, 0, 0, 0, NO, NO, 0);
        SetIntegerValue(handUp, kIOHIDEventFieldIsBuiltIn, 1);
        SetIntegerValue(handUp, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
        IOHIDEventRef f2 = [self _fingerEvent:2 identity:1
            eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
            x:x y:y isRange:NO isTouch:NO];
        AppendEvent(handUp, f2, 0); CFRelease(f2);
        [self _sendSync:handUp]; CFRelease(handUp);

        if (i + 1 < count) [NSThread sleepForTimeInterval:kMultiTapInterval];
    }
}

#pragma mark - long press

- (void)longPressAtPoint:(CGPoint)point duration:(NSTimeInterval)duration {
    if (duration <= 0) duration = 1.0;
    CGSize s = [self screenSize];
    IOHIDFloat x = point.x, y = point.y;
    IOHIDEventRef hand = CreateDigitizerEvent(
        kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1,
        kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity,
        0, x, y, 0, 0, 0, YES, YES, 0);
    SetIntegerValue(hand, kIOHIDEventFieldIsBuiltIn, 1);
    SetIntegerValue(hand, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
    IOHIDEventRef f = [self _fingerEvent:2 identity:1
        eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
        x:x y:y isRange:YES isTouch:YES];
    AppendEvent(hand, f, 0); CFRelease(f);
    [self _sendSync:hand]; CFRelease(hand);

    // tiny move to keep the touch "alive"
    NSTimeInterval elapsed = 0;
    while (elapsed < duration) {
        [NSThread sleepForTimeInterval:0.08];
        elapsed += 0.08;
        IOHIDEventRef handMove = CreateDigitizerEvent(
            kCFAllocatorDefault, mach_absolute_time(),
            kIOHIDDigitizerTransducerTypeHand, 0, 1,
            kIOHIDDigitizerEventPosition,
            0, x + 0.3, y + 0.3, 0, 0, 0, YES, YES, 0);
        SetIntegerValue(handMove, kIOHIDEventFieldIsBuiltIn, 1);
        IOHIDEventRef fm = [self _fingerEvent:2 identity:1
            eventMask:kIOHIDDigitizerEventPosition
            x:x + 0.3 y:y + 0.3 isRange:YES isTouch:YES];
        AppendEvent(handMove, fm, 0); CFRelease(fm);
        [self _sendSync:handMove]; CFRelease(handMove);
    }

    UInt32 liftMask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
                    | kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition;
    IOHIDEventRef handUp = CreateDigitizerEvent(
        kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, liftMask,
        0, x, y, 0, 0, 0, NO, NO, 0);
    SetIntegerValue(handUp, kIOHIDEventFieldIsBuiltIn, 1);
    IOHIDEventRef f2 = [self _fingerEvent:2 identity:1
        eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
        x:x y:y isRange:NO isTouch:NO];
    AppendEvent(handUp, f2, 0); CFRelease(f2);
    [self _sendSync:handUp]; CFRelease(handUp);
}

#pragma mark - swipe / drag

- (void)swipeFromPoint:(CGPoint)from toPoint:(CGPoint)to
              duration:(NSTimeInterval)duration {
    if (duration <= 0) duration = 0.3;
    IOHIDFloat x0 = from.x, y0 = from.y, x1 = to.x, y1 = to.y;

    UInt32 downMask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
                    | kIOHIDDigitizerEventIdentity;
    IOHIDEventRef hand = CreateDigitizerEvent(
        kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, downMask,
        0, x0, y0, 0, 0, 0, YES, YES, 0);
    SetIntegerValue(hand, kIOHIDEventFieldIsBuiltIn, 1);
    SetIntegerValue(hand, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
    IOHIDEventRef f = [self _fingerEvent:2 identity:1
        eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
        x:x0 y:y0 isRange:YES isTouch:YES];
    AppendEvent(hand, f, 0); CFRelease(f);
    [self _sendSync:hand]; CFRelease(hand);

    NSUInteger steps = (NSUInteger)MAX(4, duration / kMoveInterval);
    for (NSUInteger i = 1; i <= steps; i++) {
        [NSThread sleepForTimeInterval:kMoveInterval];
        IOHIDFloat t = (IOHIDFloat)i / steps;
        // ease-out curve for human-like motion
        IOHIDFloat e = 1 - (1 - t) * (1 - t);
        IOHIDFloat x = x0 + (x1 - x0) * e;
        IOHIDFloat y = y0 + (y1 - y0) * e;
        IOHIDEventRef handMove = CreateDigitizerEvent(
            kCFAllocatorDefault, mach_absolute_time(),
            kIOHIDDigitizerTransducerTypeHand, 0, 1,
            kIOHIDDigitizerEventPosition,
            0, x, y, 0, 0, 0, YES, YES, 0);
        SetIntegerValue(handMove, kIOHIDEventFieldIsBuiltIn, 1);
        IOHIDEventRef fm = [self _fingerEvent:2 identity:1
            eventMask:kIOHIDDigitizerEventPosition
            x:x y:y isRange:YES isTouch:YES];
        AppendEvent(handMove, fm, 0); CFRelease(fm);
        [self _sendSync:handMove]; CFRelease(handMove);
    }

    [NSThread sleepForTimeInterval:kFingerLiftDelay];
    UInt32 liftMask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
                    | kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition;
    IOHIDEventRef handUp = CreateDigitizerEvent(
        kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, liftMask,
        0, x1, y1, 0, 0, 0, NO, NO, 0);
    SetIntegerValue(handUp, kIOHIDEventFieldIsBuiltIn, 1);
    IOHIDEventRef f2 = [self _fingerEvent:2 identity:1
        eventMask:kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
        x:x1 y:y1 isRange:NO isTouch:NO];
    AppendEvent(handUp, f2, 0); CFRelease(f2);
    [self _sendSync:handUp]; CFRelease(handUp);
}

#pragma mark - pinch

- (void)pinchInBounds:(CGRect)bounds scale:(CGFloat)scale
                angle:(CGFloat)angle duration:(NSTimeInterval)duration {
    if (duration <= 0) duration = 0.4;
    CGPoint c = CGPointMake(CGRectGetMidX(bounds), CGRectGetMidY(bounds));
    CGFloat halfW = bounds.size.width / 2, halfH = bounds.size.height / 2;
    CGFloat cosA = cosf(angle), sinA = sinf(angle);

    // two fingers start at scale 1.0, end at `scale`
    CGPoint s1 = CGPointMake(c.x - halfW * cosA, c.y - halfW * sinA);
    CGPoint s2 = CGPointMake(c.x + halfW * cosA, c.y + halfW * sinA);
    CGPoint e1 = CGPointMake(c.x - halfW * scale * cosA, c.y - halfW * scale * sinA);
    CGPoint e2 = CGPointMake(c.x + halfW * scale * cosA, c.y + halfW * scale * sinA);

    // finger 1 down
    [self _twoFingerDown:s1 second:s2];

    NSUInteger steps = (NSUInteger)MAX(4, duration / kMoveInterval);
    for (NSUInteger i = 1; i <= steps; i++) {
        [NSThread sleepForTimeInterval:kMoveInterval];
        IOHIDFloat t = (IOHIDFloat)i / steps;
        CGPoint p1 = CGPointMake(s1.x + (e1.x - s1.x) * t, s1.y + (e1.y - s1.y) * t);
        CGPoint p2 = CGPointMake(s2.x + (e2.x - s2.x) * t, s2.y + (e2.y - s2.y) * t);
        [self _twoFingerMove:p1 second:p2];
    }
    [NSThread sleepForTimeInterval:kFingerLiftDelay];
    [self _twoFingerUp];
}

- (void)_emitHand:(IOHIDEventRef)hand
            f1:(IOHIDEventRef)f1 f2:(IOHIDEventRef)f2 {
    if (f1) { AppendEvent(hand, f1, 0); CFRelease(f1); }
    if (f2) { AppendEvent(hand, f2, 0); CFRelease(f2); }
    SetIntegerValue(hand, kIOHIDEventFieldIsBuiltIn, 1);
    SetIntegerValue(hand, kIOHIDEventFieldDigitizerIsDisplayIntegrated, 1);
    [self _sendSync:hand];
    CFRelease(hand);
}

- (void)_twoFingerDown:(CGPoint)p1 second:(CGPoint)p2 {
    UInt32 mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity;
    IOHIDEventRef hand = CreateDigitizerEvent(kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, mask, 0, p1.x, p1.y, 0, 0, 0, YES, YES, 0);
    IOHIDEventRef f1 = [self _fingerEvent:2 identity:1 eventMask:mask x:p1.x y:p1.y isRange:YES isTouch:YES];
    IOHIDEventRef f2 = [self _fingerEvent:3 identity:2 eventMask:mask x:p2.x y:p2.y isRange:YES isTouch:YES];
    [self _emitHand:hand f1:f1 f2:f2];
}

- (void)_twoFingerMove:(CGPoint)p1 second:(CGPoint)p2 {
    IOHIDEventRef hand = CreateDigitizerEvent(kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, kIOHIDDigitizerEventPosition,
        0, p1.x, p1.y, 0, 0, 0, YES, YES, 0);
    IOHIDEventRef f1 = [self _fingerEvent:2 identity:1 eventMask:kIOHIDDigitizerEventPosition x:p1.x y:p1.y isRange:YES isTouch:YES];
    IOHIDEventRef f2 = [self _fingerEvent:3 identity:2 eventMask:kIOHIDDigitizerEventPosition x:p2.x y:p2.y isRange:YES isTouch:YES];
    [self _emitHand:hand f1:f1 f2:f2];
}

- (void)_twoFingerUp {
    UInt32 mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch
                | kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition;
    IOHIDEventRef hand = CreateDigitizerEvent(kCFAllocatorDefault, mach_absolute_time(),
        kIOHIDDigitizerTransducerTypeHand, 0, 1, mask, 0, 0, 0, 0, 0, 0, NO, NO, 0);
    IOHIDEventRef f1 = [self _fingerEvent:2 identity:1 eventMask:mask x:0 y:0 isRange:NO isTouch:NO];
    IOHIDEventRef f2 = [self _fingerEvent:3 identity:2 eventMask:mask x:0 y:0 isRange:NO isTouch:NO];
    [self _emitHand:hand f1:f1 f2:f2];
}

#pragma mark - hardware keys

- (void)pressUsagePage:(UInt32)page usage:(UInt32)usage {
    IOHIDEventRef down = CreateKeyboardEvent(kCFAllocatorDefault,
        mach_absolute_time(), page, usage, YES, 0);
    [self _send:down]; CFRelease(down);
    [NSThread sleepForTimeInterval:0.06];
    IOHIDEventRef up = CreateKeyboardEvent(kCFAllocatorDefault,
        mach_absolute_time(), page, usage, NO, 0);
    [self _send:up]; CFRelease(up);
}

- (void)pressHomeButton {
    // Home = GenericDesktop page, usage 0x86 (Button 134) per vncforios.
    [self pressUsagePage:kHIDPage_GenericDesktop usage:kHIDUsage_Button_134];
}

#pragma mark - typing

- (void)typeText:(NSString *)text {
    // ASCII only via HID; complex input should go through pasteboard injection.
    static NSDictionary<NSString *, NSNumber *> *map = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableDictionary *m = [NSMutableDictionary dictionary];
        // a-z
        for (NSUInteger i = 0; i < 26; i++) {
            NSString *low = [NSString stringWithFormat:@"%c", 'a' + i];
            m[low] = @((NSUInteger)'a' - 'a' + 4 + i);         // usage 0x04..0x1D
            NSString *up = [NSString stringWithFormat:@"%c", 'A' + i];
            m[up]  = @((NSUInteger)'A' - 'A' + 4 + i);
        }
        // digits
        m[@"1"] = @30; m[@"2"] = @31; m[@"3"] = @32; m[@"4"] = @33; m[@"5"] = @34;
        m[@"6"] = @35; m[@"7"] = @36; m[@"8"] = @37; m[@"9"] = @38; m[@"0"] = @39;
        m[@" "] = @44; m[@"-"] = @45; m[@"="] = @46; m[@"["] = @47; m[@"]"] = @48;
        m[@"\\"] = @49; m[@";"] = @51; m[@"'"] = @52; m[@"`"] = @53; m[@","] = @54;
        m[@"."] = @55; m[@"/"] = @56;
        m[@"\n"] = @40;  // return
        map = m;
    });
    for (NSUInteger i = 0; i < text.length; i++) {
        unichar ch = [text characterAtIndex:i];
        NSString *key = [NSString stringWithCharacters:&ch length:1];
        NSNumber *usage = map[key];
        if (!usage) continue;
        BOOL shift = [key characterAtIndex:0] >= 'A' && [key characterAtIndex:0] <= 'Z';
        const UInt32 kHIDUsage_KeyboardLeftShift = 0xE1;
        if (shift) [self _keyDown:kHIDPage_KeyboardOrKeypad usage:kHIDUsage_KeyboardLeftShift];
        [self _keyDown:kHIDPage_KeyboardOrKeypad usage:usage.unsignedIntValue];
        [NSThread sleepForTimeInterval:0.02];
        [self _keyUp:usage.unsignedIntValue];
        if (shift) [self _keyUp:kHIDUsage_KeyboardLeftShift];
    }
}

- (void)_keyDown:(UInt32)page usage:(UInt32)usage {
    IOHIDEventRef e = CreateKeyboardEvent(kCFAllocatorDefault, mach_absolute_time(),
                                          page, usage, YES, 0);
    [self _send:e]; CFRelease(e);
}
- (void)_keyUp:(UInt32)usage {
    IOHIDEventRef e = CreateKeyboardEvent(kCFAllocatorDefault, mach_absolute_time(),
                                          kHIDPage_KeyboardOrKeypad, usage, NO, 0);
    [self _send:e]; CFRelease(e);
}

#pragma mark - event stream (raw)

- (void)sendEventStream:(NSDictionary *)stream {
    // Accepts the XCUITest-style dictionary used by TrollVNC's sendEventStream.
    // Implemented minimal: {"events":[{"inputType":"finger","touches":[
    //   {"phase":1|2|4,"x":..,"y":..,"id":N} ]}]}
    NSArray *events = stream[@"events"] ?: @[];
    for (NSDictionary *ev in events) {
        NSArray *touches = ev[@"touches"] ?: @[];
        IOHIDEventRef hand = NULL;
        for (NSDictionary *t in touches) {
            NSUInteger phase = [t[@"phase"] unsignedIntegerValue]; // 1=began 2=moved 4=ended
            IOHIDFloat x = [t[@"x"] floatValue], y = [t[@"y"] floatValue];
            UInt32 fid = [t[@"id"] unsignedIntValue] ?: 2;
            UInt32 mask;
            BOOL range = phase != 4, touch = phase != 4;
            switch (phase) {
                case 1: mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity; break;
                case 2: mask = kIOHIDDigitizerEventPosition; break;
                default: mask = kIOHIDDigitizerEventRange | kIOHIDDigitizerEventTouch | kIOHIDDigitizerEventIdentity | kIOHIDDigitizerEventPosition; break;
            }
            if (!hand) {
                hand = CreateDigitizerEvent(kCFAllocatorDefault, mach_absolute_time(),
                    kIOHIDDigitizerTransducerTypeHand, 0, 1, mask, 0, x, y, 0, 0, 0,
                    range, touch, 0);
                SetIntegerValue(hand, kIOHIDEventFieldIsBuiltIn, 1);
            }
            IOHIDEventRef f = [self _fingerEvent:fid identity:fid eventMask:mask
                x:x y:y isRange:range isTouch:touch];
            AppendEvent(hand, f, 0); CFRelease(f);
        }
        if (hand) { [self _sendSync:hand]; CFRelease(hand); }
        [NSThread sleepForTimeInterval:0.016];
    }
}

@end
