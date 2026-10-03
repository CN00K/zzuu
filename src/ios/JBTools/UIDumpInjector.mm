//  UIDumpInjector.mm
//  [zzuu-jb] See header. Must run ON the main thread of the target process.
#import "UIDumpInjector.h"
#import <UIKit/UIKit.h>

static NSDictionary *DictFromView(UIView *v, NSInteger depth, NSInteger maxDepth);

static NSMutableDictionary *ElementDict(id<UIAccessibilityIdentification> element,
                                 CGRect frame, NSString *cls) {
    NSString *label = nil, *ident = nil;
    if ([element respondsToSelector:@selector(accessibilityLabel)])
        label = [(id)element accessibilityLabel];
    if ([element respondsToSelector:@selector(accessibilityIdentifier)])
        ident = [(id)element accessibilityIdentifier];
    id value = nil;
    if ([element respondsToSelector:@selector(accessibilityValue)])
        value = [(id)element accessibilityValue];
    NSMutableDictionary *d = [NSMutableDictionary dictionary];
    d[@"class"] = cls ?: NSStringFromClass([element class]);
    if (label) d[@"label"] = label;
    if (ident) d[@"id"] = ident;
    if (value) d[@"value"] = [NSString stringWithFormat:@"%@", value];
    d[@"frame"] = @{@"x": @(frame.origin.x), @"y": @(frame.origin.y),
                    @"w": @(frame.size.width), @"h": @(frame.size.height)};
    return d;
}

static NSDictionary *DictFromView(UIView *v, NSInteger depth, NSInteger maxDepth) {
    @autoreleasepool {
        NSMutableDictionary *d = (NSMutableDictionary *)ElementDict(v, v.frame, NSStringFromClass([v class]));
        d[@"frame"] = @{@"x": @(v.frame.origin.x), @"y": @(v.frame.origin.y),
                        @"w": @(v.frame.size.width), @"h": @(v.frame.size.height)};
        if (v.hidden) d[@"hidden"] = @YES;
        if (!v.userInteractionEnabled) d[@"disabled"] = @YES;
        if (depth >= maxDepth || v.subviews.count == 0) return d;
        NSMutableArray *kids = [NSMutableArray array];
        for (UIView *sub in v.subviews) {
            [kids addObject:DictFromView(sub, depth + 1, maxDepth)];
        }
        d[@"children"] = kids;
        return d;
    }
}

NSString * _Nullable zzuuDumpUITreeJSON(NSInteger maxDepth) {
    if (maxDepth <= 0) maxDepth = 12;
    NSMutableArray *windows = [NSMutableArray array];
    for (UIWindow *w in [UIApplication sharedApplication].windows) {
        @autoreleasepool {
            NSMutableDictionary *wd = [NSMutableDictionary dictionary];
            wd[@"class"] = NSStringFromClass([w class]);
            wd[@"windowLevel"] = @(w.windowLevel);
            wd[@"frame"] = @{@"x": @(w.frame.origin.x), @"y": @(w.frame.origin.y),
                             @"w": @(w.frame.size.width), @"h": @(w.frame.size.height)};
            if (w.hidden) { wd[@"hidden"] = @YES; continue; }
            NSMutableArray *kids = [NSMutableArray array];
            for (UIView *sub in w.subviews) {
                [kids addObject:DictFromView(sub, 1, maxDepth)];
            }
            wd[@"children"] = kids;
            [windows addObject:wd];
        }
    }
    NSDictionary *root = @{@"windows": windows,
                           @"screen": @{@"w": @([UIScreen mainScreen].bounds.size.width),
                                        @"h": @([UIScreen mainScreen].bounds.size.height)},
                           @"timestamp": @([[NSDate date] timeIntervalSince1970])};
    NSData *data = [NSJSONSerialization dataWithJSONObject:root options:0 error:nil];
    if (!data) return nil;
    NSString *json = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    // Write to a well-known tmp location for the injector to pick up.
    NSString *outPath = @"/var/tmp/zzuu_uidump.json";
    [json writeToFile:outPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    return json;
}
