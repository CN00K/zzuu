//  UIDumpInjector.h
//  [zzuu-jb] UI tree dumper. Compiled as a dylib, injected into the target
//  app via dylib_inject; OR run inside zzuu's own process for self-inspection.
//  Emits a JSON view hierarchy (class, label, value, frame, hidden, enabled)
//  for every UIWindow / UIView / accessibility element.
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
extern NSString * _Nullable zzuuDumpUITreeJSON(NSInteger maxDepth);
NS_ASSUME_NONNULL_END
