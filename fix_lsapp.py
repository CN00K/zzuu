import sys

def sub(rel, old, new, tag):
    s = open(rel, encoding="utf-8").read()
    n = s.count(old)
    if n != 1:
        print(f"FAIL [{tag}]: {n}")
        sys.exit(1)
    open(rel, "w", encoding="utf-8").write(s.replace(old, new))
    print(f"ok   [{tag}]")

# FIX DeviceOffload.m: LSApplicationProxy KVC — the correct property names
# are bundleIdentifier (not applicationIdentifier) and localizedName.
# Also add icon-free robust fallback: iterate common property names.
sub("NativeOffloads/DeviceOffload.m",
'''    for (id app in apps) {
        NSString *bid = nil;
        NSString *name = nil;
        NSString *type = nil;
        @try {
            bid = [app valueForKey:@"applicationIdentifier"]
               ?: [app valueForKey:@"bundleIdentifier"] ?: @"";
            name = [app valueForKey:@"applicationDisplayName"]
                ?: [app valueForKey:@"displayName"]
                ?: [app valueForKey:@"localizedName"] ?: @"";
            type = [app valueForKey:@"applicationType"] ?: @"";
        } @catch (NSException *e) {
            continue;
        }''',
'''    for (id app in apps) {
        NSString *bid = nil;
        NSString *name = nil;
        NSString *type = nil;
        @try {
            // LSApplicationProxy property names (private class): the canonical
            // accessors are bundleIdentifier / localizedName. Try those first,
            // then legacy alternates, then direct property reads via
            // performSelector for KVC-unsafe getters.
            bid = [app valueForKey:@"bundleIdentifier"]
               ?: [app valueForKey:@"applicationIdentifier"] ?: @"";
            if ([bid length] == 0 && [app respondsToSelector:@selector(bundleIdentifier)]) {
                bid = [(NSString *(*)(id, SEL))objc_msgSend](app, @selector(bundleIdentifier)) ?: @"";
            }
            name = [app valueForKey:@"localizedName"]
                ?: [app valueForKey:@"applicationDisplayName"]
                ?: [app valueForKey:@"displayName"] ?: @"";
            if ([name length] == 0 && [app respondsToSelector:@selector(localizedName)]) {
                name = [(NSString *(*)(id, SEL))objc_msgSend](app, @selector(localizedName)) ?: @"";
            }
            type = [app valueForKey:@"applicationType"] ?: @"";
        } @catch (NSException *e) {
            continue;
        }''',
"proxy-props")

# Add objc_msgSend import (needed for performSelector fallback)
s = open("NativeOffloads/DeviceOffload.m", encoding="utf-8").read()
if "#import <objc/message.h>" not in s:
    old = "#import <objc/runtime.h>"
    new = "#import <objc/runtime.h>\n#import <objc/message.h>"
    assert s.count(old) == 1
    s = s.replace(old, new)
    open("NativeOffloads/DeviceOffload.m", "w", encoding="utf-8").write(s)
    print("ok   [objc_msgSend import]")

print("DONE")
