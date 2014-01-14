//
//  NRDigest.m
//  NRFoundation
//
//  Created by Nikolai Ruhe on 2013-11-28.
//  Copyright (c) 2012 Nikolai Ruhe. All rights reserved.
//

#import "NRDigest.h"
#import <CommonCrypto/CommonDigest.h>

#if ! defined(NR_DEFAULT_DIGEST_CLASS)
	#define NR_DEFAULT_DIGEST_CLASS NRMutableMD5Digest
#endif

// NOTE: consider support of more digest algorithms:
// - other md* and sha* variants.
// - CityHash http://en.wikipedia.org/wiki/CityHash
// - MurmurHash http://en.wikipedia.org/wiki/MurmurHash
// - SpookyHash http://www.burtleburtle.net/bob/hash/spooky.html
// we should evaluate some more algorithms regarding performance


@interface NRDigest (ForSubclassEyesOnly)

+ (NSUInteger)digestSize;

- (id)initWithPrototype:(NRMutableDigest *)prototype;

@end


@interface NRMutableDigest (ForSubclassEyesOnly)

- (void)renderDigestIntoBytes:(void *)bytes size:(NSUInteger)size;

@end


//             ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#pragma mark - ┃ NRDigest                                                                          ┃
//             ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@implementation NRDigest

- (id)init
{
	[self doesNotRecognizeSelector:_cmd];
	__builtin_unreachable();
}

- (id)initWithPrototype:(NRMutableDigest *)prototype
{
	return [super init];
}

- (id)copyWithZone:(NSZone *)zone
{
	return self;
}

- (BOOL)isEqual:(id)other
{
	if (other == self)
		return YES;
	if (! [other isKindOfClass:[NRDigest class]])
		return NO;
	return [self compare:other] == NSOrderedSame;
}

- (BOOL)isEqualToDigest:(NRDigest *)otherDigest
{
	return otherDigest == self || [self compare:otherDigest] == NSOrderedSame;
}

- (NSComparisonResult)compare:(NRDigest *)otherDigest
{
	if (otherDigest == self)
		return NSOrderedSame;

	otherDigest = [otherDigest copy];

	if ([otherDigest class] != [self class])
		return NO;

	int result = memcmp([self bytes], [otherDigest bytes], [self digestSize]);
	if (result == 0)
		return NSOrderedSame;
	return result < 0 ? NSOrderedDescending : NSOrderedAscending;
}

- (NSString *)description
{
	static const char *hexDigits = "0123456789abcdef";

	char buffer[128];

	NSUInteger length    = [self digestSize];
	const uint8_t *bytes = [self bytes];

	NSAssert(length * 2 < sizeof(buffer), @"buffer overflow");

	char *ptr = buffer;
	const char *end = ptr + length * 2;
	while (ptr != end) {
		unsigned char v = *bytes++;
		*ptr++ = hexDigits[v >> 4];
		*ptr++ = hexDigits[v & 0x0f];
	}

	return [[NSString alloc] initWithBytes:buffer
									length:length * 2
								  encoding:NSASCIIStringEncoding];
}

- (const void *)bytes
{
	[self doesNotRecognizeSelector:_cmd];
	__builtin_unreachable();
}

- (NSUInteger)digestSize
{
	[self doesNotRecognizeSelector:_cmd];
	__builtin_unreachable();
}

- (NSUInteger)hash
{
	NSUInteger hashValue;
	NSAssert([self digestSize] >= sizeof(hashValue), @"unexpectedly short digest");
	memcpy(&hashValue, [self bytes], sizeof(hashValue));
	return hashValue;
}

@end


//             ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#pragma mark - ┃ NRConstantDigest                                                                  ┃
//             ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

#define NR_CONSTANT_DIGEST(bytesize)                                             \
@interface NRConstant##bytesize##ByteDigest : NRDigest @end                      \
@implementation NRConstant##bytesize##ByteDigest { uint8_t _bytes[bytesize]; }   \
- (id)initWithPrototype:(NRMutableDigest *)prototype {                           \
	self = [super initWithPrototype:prototype];                                  \
	if (self != nil) {                                                           \
		[prototype renderDigestIntoBytes:_bytes size:bytesize];                  \
	}                                                                            \
	return self;                                                                 \
}                                                                                \
- (const void *)bytes { return _bytes; }                                         \
- (NSUInteger)digestSize { return bytesize; }                                    \
@end

NR_CONSTANT_DIGEST(8)  //  64 bit key: NRConstant8ByteDigest
NR_CONSTANT_DIGEST(16) // 128 bit key: NRConstant16ByteDigest
NR_CONSTANT_DIGEST(20) // 160 bit key: NRConstant20ByteDigest
NR_CONSTANT_DIGEST(32) // 256 bit key: NRConstant32ByteDigest


@interface NRConstantDigest : NRDigest
@end

@implementation NRConstantDigest
{
	NSData *_data;
}

+ (Class)digestClassWithDigestSize:(NSUInteger)digestSize
{
	switch (digestSize) {
		case 8:    return [NRConstant8ByteDigest  class];
		case 16:   return [NRConstant16ByteDigest class];
		case 20:   return [NRConstant20ByteDigest class];
		case 32:   return [NRConstant32ByteDigest class];

		default:
			return self;
	}
}

- (id)initWithPrototype:(NRMutableDigest *)prototype
{
	self = [super initWithPrototype:prototype];
	if (self != nil) {
		_data = [[NSMutableData alloc] initWithLength:[[prototype class] digestSize]];
		[prototype renderDigestIntoBytes:[(NSMutableData *)_data mutableBytes] size:[_data length]];
	}
	return self;
}

- (const void *)bytes
{
	return [_data bytes];
}

- (NSUInteger)digestSize
{
	return [_data length];
}

@end

//             ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#pragma mark - ┃ NRMutableDigest                                                                   ┃
//             ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@implementation NRMutableDigest
{
	NRDigest *_currentDigestCache;
}

+ (instancetype)digest
{
	Class digestClass = self;
	if (digestClass == [NRMutableDigest class])
		digestClass = [self defaultDigestClass];

	return [[digestClass alloc] initWithPrototype:nil];
}

+ (NSUInteger)digestSize
{
	[self doesNotRecognizeSelector:_cmd];
	__builtin_unreachable();
}

+ (Class)defaultDigestClass
{
	static __unsafe_unretained Class defaultDigestClass;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		NSCAssert([[NR_DEFAULT_DIGEST_CLASS class] isSubclassOfClass:[NRMutableDigest class]], @"default digest class not mutable");
		defaultDigestClass = [NR_DEFAULT_DIGEST_CLASS class];
	});

	return defaultDigestClass;
}

- (id)initWithPrototype:(NRMutableDigest *)prototype
{
	self = [super initWithPrototype:nil];
	if (self == nil)
		return nil;

	if (prototype != nil)
		_currentDigestCache = prototype->_currentDigestCache;

	return self;
}

- (void)feedBytes:(const void *)bytes length:(NSUInteger)length
{
	// must be implemented by subclasses
	[self doesNotRecognizeSelector:_cmd];
}

- (void)feedData:(NSData *)data
{
	[self feedBytes:[data bytes] length:[data length]];
}

- (void)feedString:(NSString *)string
{
	[self feedString:string encoding:NSUnicodeStringEncoding normalize:NO];
}

- (void)feedString:(NSString *)string encoding:(NSStringEncoding)encoding normalize:(BOOL)normalize
{
	if (string == nil)
		return;

	if (normalize)
		string = [string decomposedStringWithCanonicalMapping];

	if (encoding == NSUnicodeStringEncoding) {
		const UniChar *characters = CFStringGetCharactersPtr((__bridge CFStringRef)string);
		if (characters != NULL) {
			[self feedBytes:characters length:(NSUInteger)CFStringGetLength((__bridge CFStringRef)string)];
			return;
		}
	}

	[self feedData:[string dataUsingEncoding:encoding]];
}

- (void)feedDigest:(NRDigest *)digest
{
	NRDigest *immutableDigest = [digest copy];
	[self feedBytes:[immutableDigest bytes] length:[immutableDigest digestSize]];
}

- (void)digestDidChange
{
	_currentDigestCache = nil;
}

- (NSString *)description
{
	// descriptions are always done from an immutable copy
	return [[self copy] description];
}

- (id)copyWithZone:(NSZone *)zone
{
	if (_currentDigestCache == nil) {
		NSUInteger digestSize = [[self class] digestSize];
		Class digestClass = [NRConstantDigest digestClassWithDigestSize:digestSize];
		_currentDigestCache = [[digestClass alloc] initWithPrototype:self];
	}

	return _currentDigestCache;
}

- (void)renderDigestIntoBytes:(void *)bytes size:(NSUInteger)size
{
	// must be implemented by subclasses
	[self doesNotRecognizeSelector:_cmd];
	__builtin_unreachable();
}

- (id)mutableCopyWithZone:(NSZone *)zone
{
	return [[[self class] alloc] initWithPrototype:self];
}

- (NSUInteger)hash
{
	return [[self copy] hash];
}

- (NSComparisonResult)compare:(NRDigest *)otherDigest
{
	if (otherDigest == self)
		return NSOrderedSame;

	NRDigest *immutableDigest = [self copy];
	return [immutableDigest compare:otherDigest];
}

@end


//             ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#pragma mark - ┃ MD5                                                                               ┃
//             ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@implementation NRMutableMD5Digest
{
	CC_MD5_CTX _md5State;
}

+ (NSUInteger)digestSize
{
	return CC_MD5_DIGEST_LENGTH;
}

- (id)initWithPrototype:(NRMutableDigest *)prototype
{
	self = [super initWithPrototype:prototype];
	if (self == nil)
		return nil;

	if (prototype == nil) {
		CC_MD5_Init(&_md5State);
	} else {
		_md5State = ((NRMutableMD5Digest *)prototype)->_md5State;
	}

	return self;
}

- (void)feedBytes:(const void *)bytes length:(NSUInteger)length
{
	if (length == 0)
		return;

	CC_MD5_Update(&_md5State, bytes, (CC_LONG)length);
	[self digestDidChange];
}

- (void)renderDigestIntoBytes:(void *)bytes size:(NSUInteger)size
{
	CC_MD5_CTX md5State = _md5State;
	CC_MD5_Final(bytes, &md5State);
}

@end



//             ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
#pragma mark - ┃ SHA1                                                                              ┃
//             ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

@implementation NRMutableSHA1Digest
{
	CC_SHA1_CTX _sha1State;
}

+ (NSUInteger)digestSize
{
	return CC_SHA1_DIGEST_LENGTH;
}

- (id)initWithPrototype:(NRMutableDigest *)prototype
{
	self = [super initWithPrototype:prototype];
	if (self == nil)
		return nil;

	if (prototype == nil) {
		CC_SHA1_Init(&_sha1State);
	} else {
		_sha1State = ((NRMutableSHA1Digest *)prototype)->_sha1State;
	}

	return self;
}

- (void)feedBytes:(const void *)bytes length:(NSUInteger)length
{
	if (length == 0)
		return;

	CC_SHA1_Update(&_sha1State, bytes, (CC_LONG)length);
	[self digestDidChange];
}

- (void)renderDigestIntoBytes:(void *)bytes size:(NSUInteger)size
{
	CC_SHA1_CTX sha1State = _sha1State;
	CC_SHA1_Final(bytes, &sha1State);
}

@end
