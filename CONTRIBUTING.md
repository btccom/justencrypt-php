
## Contributing

 Contributions are most welcome, and the more eyes on the code the better.

 You can use the included Makefile to make CI operations easier. 

### Check list
  * Write tests - pull requests should come with full coverage
  * Check the code style

### To get started:
  * Fork this library
  * Check out the code:
    - `git clone git@github.com:yourfork/justencrypt-php && cd justencrypt-php`
  * Start your own branch:
    - `git checkout -b your-feature-branch`
  * Check your work:
    - With the Makefile:
        - Codestyle check: `make phpcs`
        - Codestyle fixer: `make phpcbf`
        - Run tests: `make phpunit`
    - With these commands:
        - Codestyle check: `vendor/bin/phpcs -n --standard=PSR1,PSR2 src test`
        - Codestyle fixer: `vendor/bin/phpcbf -n --standard=PSR1,PSR2 src test`
        - Run tests: `vendor/bin/phpunit`
        - Run tests with coverage: `vendor/bin/phpunit --coverage-html=build/doc`
  * Check code coverage: build/docs/code-coverage/index.html
  * Commit your work: `git commit ... ` (Please GPG sign your commits if possible: `git commit -S ...`)
  * Push your work:
    - `git push origin your-feature-branch`
  * And open a pull request!
