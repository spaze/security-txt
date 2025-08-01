# `security.txt` (RFC 9116) generator, parser, validator

This package is a PHP library that can generate, parse, and validate `security.txt` files. It comes with an executable script that you can use from the command line, in a CI test, or in a pipeline (for example, in GitHub Actions).

The `security.txt` document represents a text file that's both human-readable and machine-parsable to help organizations describe their vulnerability disclosure  practices to make it easier for researchers to report vulnerabilities.
The format was created by EdOverflow and Yakov Shafranovich and is specified in [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).
You can find more about <code>security.txt</code> at <a href="https://securitytxt.org/">securitytxt.org</a>.

I have also written a blogpost about `security.txt` and how it may be helpful when reporting vulnerabilities:
- [What's `security.txt` and why you should have one](https://www.michalspacek.com/what-is-security.txt-and-why-you-should-have-one) in English
- [K čemu je soubor `security.txt`](https://www.michalspacek.cz/k-cemu-je-soubor-security.txt) in Czech

# Installation

Install the package with Composer:
```
composer require spaze/security-txt
```

# As a validator

## How does the validation work
This package can validate `security.txt` file either by providing
- the file contents as a string by calling `Spaze\SecurityTxt\Parser\SecurityTxtParser::parseString()`
- a hostname like `example.com` to `Spaze\SecurityTxt\Parser\SecurityTxtParser::parseHost()`
- a URL like `https://example.com/` to `Spaze\SecurityTxt\Check\SecurityTxtCheckHost::check()`

Each of the options above will call preceding method and add more validations which are only possible in that particular case.

There's also a command line script in `bin` which uses `Spaze\SecurityTxt\Check\SecurityTxtCheckHostCli::check()` mostly just to add command line output to `Spaze\SecurityTxt\Check\SecurityTxtCheckHost::check()`.

If you want to decouple fetching the `security.txt` file and parsing it, there's also a possibility to pass a `SecurityTxtFetchResult` object to `Spaze\SecurityTxt\Parser\SecurityTxtParser::parseFetchResult()`.

## How to use the validator
`Spaze\SecurityTxt\Check\SecurityTxtCheckHost::check()` is probably what you'd want to use as it provides the most comprehensive checks, can pass a URL, not just a hostname, and also supports callbacks. It accepts these parameters:

`string $url`

A URL where the file will be looked for, you can pass just for example `https://example.com`, no need to use the full path to the `security.txt` file, because only the hostname of the URL will be used for further checks

`?int $expiresWarningThreshold = null`

The validator will start throwing warnings if the file expires soon, and you can say what "soon" means by specifying the number of days here

`bool $strictMode = false`

If you enable strict mode, then the file will be considered invalid, meaning `SecurityTxtCheckHostResult::isValid()` will return `false` even when there are only warnings, with strict mode disabled, the file with only warnings would still be valid and `SecurityTxtCheckHostResult::isValid()` would return `true`

`bool $noIpv6 = false`

Because some environments do not support IPv6, looking at you GitHub Actions

`Spaze\SecurityTxt\Check\SecurityTxtCheckHost::check()` returns a `Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult` object with some obvious and less obvious properties.
The less obvious ones can be obtained with the following methods. All of them return an array of `SecurityTxtSpecViolation` descendants.

### `getFetchErrors()`
Returns `list<SecurityTxtSpecViolation>` and contains errors encountered when fetching the file from a server. For example but not limited to:
- When the content type or charset is wrong
- When the URL scheme is not HTTPS

### `getFetchWarnings()`
Also returns `list<SecurityTxtSpecViolation>` and has warnings when fetching the file, like for example but not limited to:
- When the files at `/security.txt` and `/.well-known/security.txt` differ
- When `/security.txt` does not redirect to `/.well-known/security.txt`

### `getLineErrors()`
Returns `array<int, list<SecurityTxtSpecViolation>>` where the array `int` key is the line number. Contains errors discovered when parsing and validating the contents of the `security.txt` file. These errors are produced by any class that implements the `FieldProcessor` interface. The errors include but are not limited to:
- When a field uses incorrect separators
- When a field value is not URL or the URL doesn't use `https://` scheme

### `getLineWarnings()`
Also returns `array<int, list<SecurityTxtSpecViolation>>` where the array `int` key is the line number. Contains warnings generated by any class that implements the `FieldProcessor` interface, when parsing and validating the contents of the `security.txt` file. These warnings include but are not limited to:
- When the `Expires` field's value is too far into the future

### `getFileErrors()`
Returns `list<SecurityTxtSpecViolation>`, the list contains file-level errors which cannot be paired with any single line. These error are generated by `FieldValidator` child classes, and include:
- When mandatory fields like `Contact` or `Expires` are missing

### `getFileWarnings()`
Returns `list<SecurityTxtSpecViolation>`, the list contains file-level warnings that cannot be paired with any single line. These warnings are generated by `FieldValidator` child classes, and include for example:
- When the file is signed, but there's no `Canonical` field

## Callbacks
`SecurityTxtCheckHost::check()` supports callbacks that can be set with `SecurityTxtCheckHost::addOn*()` methods. You can use them to get the parsing information in "real time", and are used for example by the `bin/checksecuritytxt.php` script via the `\Spaze\SecurityTxt\Check\SecurityTxtCheckHostCli` class to print information as soon as it is available.

## JSON
The `Spaze\SecurityTxt\Check\SecurityTxtCheckHostResult` object can be encoded to JSON with `json_encode()`,
and decoded back with `Spaze\SecurityTxt\Check\SecurityTxtJson::createCheckHostResultFromJsonValues()`.

Exceptions can be recreated with `Spaze\SecurityTxt\Check\SecurityTxtJson::createFetcherExceptionFromJsonValues()`.

## The other methods
Both `Spaze\SecurityTxt\Parser\SecurityTxtParser::parseString()` and `Spaze\SecurityTxt\Parser\SecurityTxtParser::parseHost()` return a `Spaze\SecurityTxt\Parser\SecurityTxtParseResult` object with similar methods as what's described above for `SecurityTxtCheckHostResult`.
The result returned from `parseHost()` also contains `Spaze\SecurityTxt\Fetcher\SecurityTxtFetchResult` object.

# As a writer
You can create a `security.txt` file programmatically:
1. Create a `SecurityTxt` object
2. Add what's needed
3. Pass it to `SecurityTxtWriter::write()` it will return the `security.txt` contents as a string

See below if you want to add an OpenPGP signature.

## Value validation
By default, values are validated when set, and an exception is thrown when they're invalid. You can set validation level in the `SecurityTxt` constructor using the `SecurityTxtValidationLevel` enum:
- `NoInvalidValues` (an exception will be thrown, and the value won't be set, this is the default setting)
- `AllowInvalidValues` (an exception will be thrown but the value will still be set)
- `AllowInvalidValuesSilently` (an exception will not be thrown, and the value will be set)

You can use the following `SecurityTxt` constants to serve the file with correct HTTP content type:
- `SecurityTxt::CONTENT_TYPE_HEADER`, the value to be sent as `Content-Type` header value (`text/plain; charset=utf-8`);
- `SecurityTxt::CONTENT_TYPE`, the correct content type `text/plain`
- `SecurityTxt::CHARSET`, the correct charset as `charset=utf-8`

## Example
```php
$securityTxt = new SecurityTxt();
$securityTxt->addContact(new SecurityTxtContact('https://contact.example'));
$securityTxt->addContact(SecurityTxtContact::phone('123456'));
$securityTxt->addContact(SecurityTxtContact::email('email@com.example'));
$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('https://ack1.example'));
$securityTxt->setExpires(new SecurityTxtExpiresFactory()->create(new DateTimeImmutable('+3 months midnight')));
$securityTxt->addAcknowledgments(new SecurityTxtAcknowledgments('ftp://ack2.example'));
$securityTxt->setPreferredLanguages(new SecurityTxtPreferredLanguages(['en', 'cs-CZ']));
header('Content-Type: ' . SecurityTxt::CONTENT_TYPE_HEADER);
echo new SecurityTxtWriter()->write($securityTxt);
```

## Signing the file
One option to sign the file using an OpenPGP cleartext signature as per the `security.txt` [specification](https://www.rfc-editor.org/rfc/rfc9116#name-digital-signature) is to pre-sign the `security.txt` file using the `gpg` command line utility and store the result as a static file in your repository.
I'd recommend creating the signatures that way as it doesn't expose your private keys to the web server and the web app. Allowing the app and the server to access your private keys brings a handful of new security problems to solve, which some of them are mentioned below.

Creating a new signing key is beyond the scope of this document, but you can refer to sources like [the GitHub Docs](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key).
Related challenges like key distribution, secure storage, and expiration, while interesting to address properly, are also not covered here.

Having said that, this library also allows you to create the signature programmatically by calling `Spaze\SecurityTxt\Signature\SecurityTxtSignature::sign()`:
```php
$gnuPgProvider = new SecurityTxtSignatureGnuPgProvider();
$signature = new SecurityTxtSignature($gnuPgProvider);
$securityTxt = new SecurityTxt();
// $securityTxt->addContact(...) etc.
$writer = new SecurityTxtWriter();
$contents = $writer->write($securityTxt);
$signingKeyFingerprint = '...'; // Or anything that refers to a unique key (user id, key id, ...)
$keyPassphrase = '...'; // Don't commit the passphrase to Git, please don't
echo $signature->sign($contents, $signingKeyFingerprint, $keyPassphrase);
```

The `SecurityTxtSignature::sign()` method makes use of the keyring of the current user (which may be a web server user).
This keyring is normally located in the `.gnupg` directory in the user's home dir. To specify a custom location,
pass the path to the keyring in the `Spaze\SecurityTxt\Signature\Providers\SecurityTxtSignatureGnuPgProvider` constructor, for example:
```php
$gnuPgProvider = new SecurityTxtSignatureGnuPgProvider('/home/www');
```
If you wish, you can instead store the path to the keyring in the environment variable `GNUPGHOME`.
Make sure the keyring is not publicly accessible, do not store keyring in `public_html` or similar directories. Also don't add the keyring to your Git repository.

If you're going to use a key for this library, I'd strongly recommend you create a key only to sign the file and do not use the key for anything else. You can then sign the key with your main key, if you want.

### Caching the signed file
If you're going to create the signature using this library, I don't recommend doing it on each request. Instead, you can cache the signed contents using for example the [Symfony Cache](https://symfony.com/doc/current/components/cache.html) component:
```php
use Symfony\Component\Cache\Adapter\FilesystemAdapter;
use Symfony\Contracts\Cache\ItemInterface;

$cache = new FilesystemAdapter();
$cachedContents = $cache->get('securitytxt_file', function (ItemInterface $item) use ($securityTxt, $signature, $contents, $signingKeyFingerprint, $keyPassphrase): string {
    $item->expiresAt($securityTxt->getExpires()->getDateTime());
    return $signature->sign($contents, $signingKeyFingerprint, $keyPassphrase);
});

echo $cachedContents;
```
The following example uses the [Nette Cache](https://doc.nette.org/en/caching) library, the code is very similar to the example above:
```php
use Nette\Caching\Cache;
use Nette\Caching\Storages\FileStorage;

$storage = new FileStorage('/tmp/cache');
$cache = new Cache($storage);
$cachedContents = $cache->load('securitytxt_file', function () use ($signature, $contents, $signingKeyFingerprint, $keyPassphrase): string {
    return $signature->sign($contents, $signingKeyFingerprint, $keyPassphrase);
}, [Cache::Expire => $securityTxt->getExpires()->getDateTime()]);

echo $cachedContents;
```

# Command line usage
The `checksecuritytxt.php` script, located in the `bin` directory, prints progress and validation errors and warnings. It can be used from the command line or in automated tests.

Usage:
```sh
checksecuritytxt.php <URL or hostname> [days] [--colors] [--strict] [--no-ipv6]
```

Parameters:
- `URL or hostname`: A hostname or a domain you want to check (e.g. `example.com`). If you provide a URL (e.g., `https://example.com/foo`), the script will extract and use only the hostname part anyway.
- `days`: If the file expires in less than *`days`* days, the script will print a warning.
- `--colors`: Enables colored output using red, green, and other colors for better readability.
- `--strict`: Upgrades all warnings to errors, enforcing stricter validation.
- `--no-ipv6`: Disables IPv6 usage. When this option is set, the script effectively ignores AAAA DNS records and uses only A records.

The script returns the following status codes:
- `0`: The file is valid.
- `1`: Returned if any of the following conditions are true:
  - The file has expired.
  - The file has errors.
  - The file has warnings when using `--strict`.
- `2`: No hostname or URL was passed.
- `3`: The file cannot be loaded.

# CI Pipelines
If you'd like to check your `security.txt` file automatically using a CI (continuous integration) platform, such as GitHub Actions, you can use the command-line script described above.
In general, you’ll need to follow these steps:

1. Install PHP if it is not already installed.
2. Install this package using Composer.
3. Run the `checksecuritytxt.php` script.

You can use my own checks as a template or for inspiration; see [the `securitytxt.yml` file](https://github.com/spaze/michalspacek.cz/blob/main/.github/workflows/securitytxt.yml) in my repository.

# Exceptions
The messages in the exceptions as thrown by this library do not contain any sensitive information and are safe to display to the user using the `getMessage()` method.
But please be aware that the messages contain server-supplied information, so please do not display the messages as HTML or do not feed them into a Markdown parser or similar.
If you'd do that, a malicious server could inject content that would result in Cross-Site Scripting attack for example.

## Formatting messages
If you'd like to format some of the values contained in the messages, you can use the exception's `getMessageFormat()` and `getMessageValues()` methods.
The `getMessageFormat()` method will return an error message with `%s` placeholders, while `getMessageValues()` will return the values, including the server-supplied ones,
which you can, **after a proper sanitization and/or escaping**, wrap in `<code>` tags for example, and use them to replace the placeholders.

The same goes for formatting `SecurityTxtSpecViolation` object messages: you can use `getMessageFormat()` and `getMessageValues()`, and also `getHowToFixFormat()` and `getHowToFixValues()`.
