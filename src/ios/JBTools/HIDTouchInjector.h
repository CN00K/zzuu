//  HIDTouchInjector.h
//  [zzuu-jb] System-wide touch injection via IOKit HID (iOS 14.8-18.x).
//  Port of TrollVNC's STHIDEventGenerator + zxtouch Touch.xm ideas,
//  trimmed to what an agent needs: tap / doubleTap / longPress / swipe /
//  drag / pinch / key / text. All coordinates in POINTS (screen space).
//
//  Entitlements required (already in Minis.entitlements, see [3/7]):
//    com.apple.private.hid.client.event-dispatch
//    com.apple.private.hid.client.event-monitor
//    com.apple.private.hid.client.service-protected
//    com.apple.private.hid.manager.client
//    com.apple.backboard.client
//    iokit-user-client-class += IOHIDLibUserClient

#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

NS_ASSUME_NONNULL_BEGIN

@interface HIDTouchInjector : NSObject

/// Singleton. lazily creates the IOHIDEventSystemClient.
+ (instancetype)shared;

/// Screen size in points (main screen, portrait-native orientation).
- (CGSize)screenSize;

/// Simple tap.
- (void)tapAtPoint:(CGPoint)point;
- (void)doubleTapAtPoint:(CGPoint)point;

/// Long press with duration (seconds, default 1.0 when <= 0).
- (void)longPressAtPoint:(CGPoint)point duration:(NSTimeInterval)duration;

/// Swipe / drag from A to B over `duration` seconds (default 0.3).
- (void)swipeFromPoint:(CGPoint)from toPoint:(CGPoint)to
              duration:(NSTimeInterval)duration;

/// Two-finger pinch inside `bounds` (screen points).
/// scale > 1 = zoom in, < 1 = zoom out. angle in radians.
- (void)pinchInBounds:(CGRect)bounds scale:(CGFloat)scale
                angle:(CGFloat)angle duration:(NSTimeInterval)duration;

/// Hardware key press (usage page + usage, e.g. home button).
- (void)pressUsagePage:(UInt32)page usage:(UInt32)usage;

/// Home button.
- (void)pressHomeButton;

/// Type ASCII text through the HID keyboard path.
- (void)typeText:(NSString *)text;

/// Send a raw event-stream dictionary (XCTEvent format, like XCUITest's).
- (void)sendEventStream:(NSDictionary *)stream;

@end

NS_ASSUME_NONNULL_END
