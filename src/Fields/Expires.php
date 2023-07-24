<?php
declare(strict_types = 1);

namespace Spaze\SecurityTxt\Fields;

use DateInterval;
use DateTimeImmutable;

class Expires
{

	private DateInterval $interval;


	public function __construct(
		private readonly DateTimeImmutable $dateTime,
	) {
		$this->interval = (new DateTimeImmutable())->diff($this->dateTime);
	}


	public function isExpired(): bool
	{
		return $this->interval->invert === 1;
	}


	public function inDays(): int
	{
		$days = (int)$this->interval->days; // $this->interval is created by diff() so days is always set
		return $this->isExpired() ? -$days : $days;
	}


	public function getDateTime(): DateTimeImmutable
	{
		return $this->dateTime;
	}

}
