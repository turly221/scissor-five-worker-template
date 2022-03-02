## Guidelines
1. record your requirements, dependencies and environment configurations in dockerfile
2. develop inside the container

## how to run the project
1. Build docker image
   `docker-compose build`
2. Start service
   `docker-compose up -d`
3. Test inside docker container
   `docker exec -it testworker bash`
