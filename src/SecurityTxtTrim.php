<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt;

/**
 * What `trim()`, `rtrim()` and `ltrim()` remove by default since PHP 8.6, which added the form feed, passed explicitly so that PHP 8.5 removes the same: once PHP 8.6 is
 * required, this class is deleted and every call static analysis then reports goes back to the default.
 */
final class SecurityTxtTrim
{

	public const string CHARACTERS = " \n\r\t\v\f\0";

}
