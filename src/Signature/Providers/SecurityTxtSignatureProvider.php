<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Signature\Providers;

use SensitiveParameter;
use Spaze\SecurityTxt\Signature\SecurityTxtSignatureErrorInfo;

interface SecurityTxtSignatureProvider
{

	public function addSignKey(string $fingerprint, #[SensitiveParameter] string $passphrase = ''): bool;


	public function getErrorInfo(): SecurityTxtSignatureErrorInfo;


	public function sign(string $text): false|string;

}
