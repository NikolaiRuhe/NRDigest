//
//  NRDigest.h
//  NRFoundation
//
//  Created by Nikolai Ruhe on 2013-11-28.
//  Copyright (c) 2012 Nikolai Ruhe. All rights reserved.
//

#import <Foundation/Foundation.h>

#define NR_UNAVAILABLE(msg) __attribute__((unavailable(msg)))



@interface NRDigest : NSObject <NSCopying>

// Do not use alloc init to create instances. The only way to create immutable digest
// instances is by creating a copy of a mutable instance.
- (id)init NR_UNAVAILABLE("use [NRMutableDigest digest] to create instances");

// This is the fast path digest comparison.
- (NSComparisonResult)compare:(NRDigest *)other;

- (BOOL)isEqualToDigest:(NRDigest *)digest;

// Other methods inherited from NSObject that work as expected are
// isEqual
// hash
// copy

@end



@interface NRMutableDigest : NRDigest <NSMutableCopying>

+ (instancetype)digest;

- (void)feedBytes:(const void *)bytes length:(NSUInteger)length;
- (void)feedData:(NSData *)data;
- (void)feedString:(NSString *)string;
- (void)feedString:(NSString *)string encoding:(NSStringEncoding)encoding normalize:(BOOL)normalize;
- (void)feedDigest:(NRDigest *)digest;
//- (void)feedPropertyList:(id)plist;
//- (void)feedContentsOfFile:(NSString *)filepath;

+ (Class)defaultDigestClass;
+ (void)setDefaultDigestClass:(Class)defaultDigestClass;

@end



@interface NRMutableMD5Digest     : NRMutableDigest @end
@interface NRMutableSHA1Digest    : NRMutableDigest @end
