build:
	DOCKER_BUILDKIT=1 docker build -t wolfy:latest --target=runtime .

init:
	@docker run -e WOLFY_PUT_PASSWORD=${WOLFY_PASSWORD} -e WOLFY_PUT_SALT=${WOLFY_SALT} wolfy:latest put -k $(k) -v $(v) > data

append:
	@echo "$(file < data)" | docker run -i -e WOLFY_PUT_PASSWORD=${WOLFY_PASSWORD} -e WOLFY_PUT_SALT=${WOLFY_SALT} wolfy:latest put -k $(k) -v $(v) -i '-' > data

query:
	@echo "$(file < data)" | docker run -i -e WOLFY_QUERY_PASSWORD=${WOLFY_PASSWORD} -e WOLFY_QUERY_SALT=${WOLFY_SALT} wolfy:latest query -p $(p) -i '-'