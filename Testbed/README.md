# Full VEREFOO IDS demo

## Requirements

### Mandatory

- [Ubuntu 20.04 LTS](https://releases.ubuntu.com/20.04/). For reference, the utilized virtual machine configuration was:
  50 GB disk space, 4 GB RAM, and 4 CPU cores
- [Docker Engine](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose standalone](https://docs.docker.com/compose/install/standalone/)
- **openjdk-1.8**:
  ```
  sudo apt install openjdk-8-jdk
  ```
- **curl**:
  ```
  sudo apt install curl
  ```
- **Python's package manager** (Ubuntu 20.04 already includes Python 3.8 by default):
  ```
  sudo apt install python3-pip
  ```
- Download [z3-4.8.15-x64-glibc-2.31.zip](https://github.com/Z3Prover/z3/releases/tag/z3-4.8.15).
  Newer versions may have some problems with the VEREFOO framework. After downloading the archive, extract its contents,
  rename the folder to `z3` and move it to `/home`. After doing it, add these lines to `~/.bashrc`:
  ```
  LD_LIBRARY_PATH=/home/z3/bin/ 
  Z3=/home/z3/bin/
  ```

### Optional

- Download and install [cypher-shell 1.1.15](https://github.com/neo4j/cypher-shell/releases/download/1.1.15/cypher-shell_1.1.15_all.deb)
  and [neo4j 3.5.25](https://go.neo4j.com/download-thanks.html?edition=community&release=3.5.25&flavour=deb):
  ```
  sudo apt install ./cypher-shell_1.1.15_all.deb
  sudo apt install ./neo4j_3.5.25_all.deb
  ```
  In case links are broken, you can find both `.deb` files inside the `neo4j-files` directory of the `ids-demo` branch of VEREFOO
- After installing neo4j, start it by running:
  ```
  sudo /usr/bin/neo4j console
  ```
- Visit `http://localhost:7474/` and log in with username `neo4j` and password `neo4j`.
  When prompted, set your new password to `costLess`
- The network topology image was created with [yEd Graph Editor](https://www.yworks.com/products/yed/download#download),
  using network palettes from [this GitHub repository](https://github.com/gowenrw/yEd_network_palettes)

## Starting the demo

```
python3 startDemo.py
```

## Useful commands

- Restart the Docker service if issues arise:
  ```
  sudo systemctl restart docker
  ```
- Start and run services defined in the given Docker Compose file:
  ```
  sudo docker-compose -f <DOCKER_COMPOSE_FILE> up
  ```
- Stop and remove services defined in the given Docker Compose file:
  ```
  sudo docker-compose -f <DOCKER_COMPOSE_FILE> down
  ```
- List all containers, including stopped ones:
  ```
  sudo docker ps -a
  ```
- Remove specified container:
  ```
  sudo docker rm <CONTAINER>
  ```
- Remove all containers
  ```
  sudo docker rm $(sudo docker ps -a -q)
  ```
- List all images:
  ```
  sudo docker image ls
  ```
- Remove specified image:
  ```
  sudo docker rmi <IMAGE>
  ```
- Remove unused images:
  ```
  sudo docker image prune
  ```
- Remove unused networks:
  ```
  sudo docker network prune
  ```
- Build image from specified Dockerfile:
  ```
  sudo docker build -t <IMAGE_NAME> <PATH_TO_DOCKERFILE_FOLDER>
  ```
- Create container without starting it:
  ```
  sudo docker create --name <CONTAINER_NAME> <IMAGE_NAME>
  ```
- Execute interactive command in running container:
  ```
  sudo docker exec -it <CONTAINER> <COMMAND>
  ```
- Start specified container:
  ```
  sudo docker start <CONTAINER>
  ```
- Stop specified container:
  ```
  sudo docker stop <CONTAINER>
  ```
- Stop all containers
  ```
  sudo docker stop $(sudo docker ps -a -q)
  ```