.PHONY: test test-cov lint clean docker-build

IMAGE_NAME := php-authclient-test
DOCKER_RUN := docker run --rm -v $(CURDIR):/app -w /app $(IMAGE_NAME)

docker-build:
	@docker build -q -t $(IMAGE_NAME) -f Dockerfile.test . > /dev/null

test: docker-build
	$(DOCKER_RUN) vendor/bin/phpunit --testdox

test-cov: docker-build
	$(DOCKER_RUN) sh -c "XDEBUG_MODE=coverage vendor/bin/phpunit --coverage-text"

lint: docker-build
	$(DOCKER_RUN) vendor/bin/phpstan analyse src/ --level=6

clean:
	rm -rf vendor/ composer.lock .phpunit.cache