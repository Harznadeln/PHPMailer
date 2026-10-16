# Practical Work 3 - POP3 Characterization Tests

Module: src/POP3.php
Framework: PHPUnit 9.6
Coverage: Xdebug 3

## Install dependencies

composer install

## Run characterization tests

.\vendor\bin\phpunit.bat --no-coverage .\test\PHPMailer\POP3CharacterizationTest.php

## Generate coverage report

$env:XDEBUG_MODE = "coverage"
.\vendor\bin\phpunit.bat --coverage-filter .\src\POP3.php --coverage-text --coverage-html .\coverage-pr3-after

## Results

Characterization tests: 22 passed, 70 assertions.
Initial POP3 line coverage: 0% (0/100).
Final POP3 line coverage: 95% (95/100).
Source code of POP3.php was not modified.

PHPUnit configuration: phpunit.xml.dist
