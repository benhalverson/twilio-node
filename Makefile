test-install:
	npm install mocha -g

install:
	npm install ./

test:
	mocha spec
