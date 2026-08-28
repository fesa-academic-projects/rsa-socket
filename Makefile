.PHONY: build test slides bench attack fmt diff clean

build:
	python3 build.py

test: build
	python3 python/test_all.py

slides: build
	python3 python/slides.py

bench: build
	python3 python/bench.py

attack: build
	python3 python/attack.py

fmt:
	clang-format -i include/*.h src/*.c
	black build.py python/*.py

diff:
	@echo '=== Simple_tcpServer.py ==='
	@diff -u --strip-trailing-cr original/Simple_tcpServer.py python/Simple_tcpServer.py || true
	@echo
	@echo '=== Simple_tcpClient.py ==='
	@diff -u --strip-trailing-cr original/Simple_tcpClient.py python/Simple_tcpClient.py || true

clean:
	rm -rf python/_rsa.c python/*.o python/*.so python/__pycache__ python/home
