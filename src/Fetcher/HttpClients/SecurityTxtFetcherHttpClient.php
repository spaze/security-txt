<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fetcher\HttpClients;

use Spaze\SecurityTxt\Fetcher\SecurityTxtFetcherResponse;

interface SecurityTxtFetcherHttpClient
{

	public function getResponse(string $url, ?string $contextHost): SecurityTxtFetcherResponse;

}
