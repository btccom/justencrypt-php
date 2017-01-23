test: phpunit phpcs

.PHONY: test phpunit phpcs

pretest:
		if [ ! -d build ]; then mkdir build; fi
		if [ ! -d vendor ] || [ ! -f composer.lock ]; then composer install; else echo "Already have dependencies"; fi

phpunit: pretest
		vendor/bin/phpunit --coverage-text --coverage-clover=build/coverage.clover --coverage-html=build/doc

phpunit-ci: pretest
		vendor/bin/phpunit --coverage-text --coverage-clover=build/coverage.clover

test-examples: pretest
		./validate_examples.sh

ifndef STRICT
STRICT = 0
endif

ifeq "$(STRICT)" "1"
phpcs: pretest
		vendor/bin/phpcs --standard=PSR1,PSR2 src test/
else
phpcs: pretest
		vendor/bin/phpcs --standard=PSR1,PSR2 -n src test/
endif

phpcbf: pretest
		vendor/bin/phpcbf --standard=PSR1,PSR2 src/ test/

ocular:
		wget https://scrutinizer-ci.com/ocular.phar

ifdef OCULAR_TOKEN
scrutinizer: ocular
		@php ocular.phar code-coverage:upload --format=php-clover build/coverage.clover --access-token=$(OCULAR_TOKEN);
else
scrutinizer: ocular
		php ocular.phar code-coverage:upload --format=php-clover build/coverage.clover;
endif

clean: clean-env clean-deps

clean-env:
		rm -rf coverage.clover
		rm -rf ocular.phar
		rm -rf build

clean-deps:
		rm -rf vendor/

