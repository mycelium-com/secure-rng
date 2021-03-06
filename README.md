# Secure random number generator module

### What is this?

It's a compact and simple implementation of cryptographically-secure deterministic pseudo-random number generator on top of hardware AES instructions.

### Why do I need it?

https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator

### What hardware do I need to get this working?

* Intel AES-NI and Armv8 Cryptographic Extension are supported.
* A software implementation is used if none of these are available for target platform.

### Limitations

* Each context instance is able to provide only a limited amount of generation rounds. Once a limit is exhausted, any attempt to generate new data will return RNG_NEED_RESEED error. This limit is hardcoded to 2^48 invocations.

* You may deal with previous limitation by enabling prediction resistance. This may be done using the ```secure_rng_set_seeder``` API function. If this feature is enabled then generator instance will be reseeded automatically with specified interval.

* You may not generate more than 2^16 bytes through single invocation. If you need more data then use a loop to perform sufficient amount of ```secure_rng_bytes``` invocations.

### API

Before using the generator, you must create and initialize context structure with entropy bytes. Entropy bytes buffer must be exactly 48 bytes long, though you may provide additional data through ```personalization_string``` and ```additional_data``` parameters.

```C
/*
 * SET(ctx, seeder, interval)
 * Force generator to invoke seeder function on every interval invocations of secure_rng_bytes.
 * Seeder function must fill the received buffer with 48 bytes of entropy data. 
 * Note that it is senseless to use PRNG for seeding. Use only true sources of randomness for seeding.
 */
void secure_rng_set_seeder(struct secure_rng_ctx *ctx, void (*resistance_seeder_function)(uint8_t seed_out[48]), uint64_t reseed_interval);
```

```C
/**
 * SEED(ctx, entropy, personalization)
 * Init generator instance with provided 48 bytes of entropy and personalization id.
 * Returns RNG_SUCCESS result when completed successfully.
 */
int secure_rng_seed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *personalization_string, size_t personalization_len);
```

```C
/**
 * PUT(ctx, entropy, additional)
 * Update generator instance state with provided 48 bytes of entropy and additional data.
 * Returns RNG_SUCCESS result when completed successfully.
 */
int secure_rng_reseed(struct secure_rng_ctx *ctx, const uint8_t entropy_input[48], const uint8_t *additional_data, size_t additional_data_len);
```

```C
/**
 * GET(ctx, bytes, length, resistance)
 * Get length of generated bytes from generator instance. Returns status when completed.
 * Returns RNG_SUCCESS result when completed successfully.
 */
int secure_rng_bytes(struct secure_rng_ctx *ctx, uint8_t *x, size_t xlen, int resistance);
```
