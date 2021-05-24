---
layout: post
title:  "Docker for a django project"
description: ""
permalink: /ppl/django-for-a-django-project/
---

## English
![Error](https://www.docker.com/sites/default/files/d8/styles/role_icon/public/2019-07/Docker-Logo-White-RGB_Vertical-BG_0.png)<br>
_source: https://www.docker.com/sites/default/files/d8/styles/role\_icon/public/2019-07/Docker-Logo-White-RGB\_Vertical-BG\_0.png_

As a programmer, just knowing how to write code is not enough. Running the code on a server effectively and effieciently, while also being easily maintainable and scalable is a required skill. Just for this, a tool called Docker was developed.

In this blog post, I hope to give a short explanation on how to run a simple django project (in this case it is the django rest project used by my groups PPL project, TBCare) using docker.

<br>

### What is docker
Docker is an app to easily create, deploy, and run code. Deforehand, this was done using apache or nginx (and still is used in docker), but instead of an entire server being used just to run a single project of code, docker creates what is known as docker containers. In docker, there are two important concepts to understand, docker images and docker containers.

For an easy explanation, think of our source code as well, source code. Docker will pack our source code in to a neat structure called a docker image. This usually means it will prepare all the necessary requirements which we have already set in a Dockerfile (I will show an example later). Docker then gives us the option to "run" the image. A running docker image is what is called a docker container.

![Error](https://geekflare.com/wp-content/uploads/2019/07/dockerfile-697x270.png)<br>
_source: https://geekflare.com/wp-content/uploads/2019/07/dockerfile-697x270.png_

### Preparation
To follow this guide, you need to install docker engine and docker compose. You can view the [docker engine installation page](https://docs.docker.com/engine/install/) to see how to install it. For docker compose, you can install it from [pypi](https://pypi.org/project/docker-compose/)

We also need a django project, so I will use TBCare's backend repository which is a django rest project.

![Error](/assets/images/PPL/Docker/1.png)

For this guide, I will be using a linux system running Ubuntu 20.04

### Dockerfile
A dockerfile is a set of instruction used to create a docker image. Think of writing a Dockerfile as writing a program. Here is an example of doing so:

Step 1: FROM<br>
![Error](/assets/images/PPL/Docker/2.png)

FROM is used to include a base docker image for our docker image. It may seem confusing, but image it as using libraries when writing a C program or a python program. Since we can't build a program from 100% scratch, we instead use previous images already made for us. The FROM command here is the same

In this project, we care using a base docker image that has the necessary requirements for a python project.

Step 2: WORKDIR<br>
![Error](/assets/images/PPL/Docker/3.png)

WORKDIR is a command to set the directory in a docker container. Think of a container as a linux system, this is the folder in that linux system. Here is set it to /opt, but you can use /app, /project, anything really.

Step 3: COPY <br>
![Error](/assets/images/PPL/Docker/4.png)

COPY is a command to copy files from the folder outside the docker container, into the docker container. Here I am copying everything needed to run the project.

Step 4: RUN <br>
![Error](/assets/images/PPL/Docker/5.png)

RUN is a command to well, run bash commands. We used this to prepare the container, such as installing requirements and other prerequisites.

Step 5: ENTRYPOINT <br>
![Error](/assets/images/PPL/Docker/6.png)

ENTRYPOINT is a command that will run when the container is to be run. In this case, I want to run `/opt/docker-entrypoint.sh`, which is the bash file that contains this code:

```bash
#!/bin/sh

python manage.py collectstatic --no-input
python manage.py migrate

exec "$@"
```

STEP 6: CMD <br>
![Error](/assets/images/PPL/Docker/7.png)

CMD is like ENTRYPOINT, but the parameters provided in CMD can be changed using the command line, unlike ENTRYPOINT.

<br>

### docker-compose
Docker compose was created to ease the building of a docker image. Before, we had to use the `docker` command, where the parameters needed to do so can be very long and tedious. Instead, docker-compose neatly wraps all of it into a YAML file, so all we have to do is write that YAML file.

This is the YAML file I will be using

![Error](/assets/images/PPL/Docker/8.png)

version is the version of docker-compose I am using. Version 3 isn't necessary the latest but it's good enough. services will list all the services I will build. app is the name of the service. 

build denotes the project location. Since my docker-compose.yml file is in the same directory as the project, I just have to set this to `.`.

ports is the binding of the container port to the system port. As we saw in the dockerfile, we are running the project on port 8000. Since I just want everything to be consistent, I set the system port to 8000 as well. If I wanted to set the system port to 9000, I would write "9000:8000".

environment is the environment variables I want to use. Python has a PYTHONUNBUFFERED environment variable which denotes whether or not the python program will buffer strings or not. I choose not to buffer the strings.

There are more settings, which you can read about [here](https://docs.docker.com/compose/compose-file/compose-file-v3/)

<br>

### Running the project
To run the project, we first need to build the docker image. This is done using docker-compose with the command:

```bash
$ docker-compose build
```

![Error](/assets/images/PPL/Docker/9.png)

![Error](/assets/images/PPL/Docker/10.png)

Now our image is built. There is no container yet, but we can run the image using docker-compose up

![Error](/assets/images/PPL/Docker/11.png)

![Error](/assets/images/PPL/Docker/12.png)

Now that the container is running we can just check django-admin

![Error](/assets/images/PPL/Docker/13.png)

We have succesfully run our project using docker :)

### Conclusion
Docker is a very powerful tool, allowing the deployment of project be faster and easier. Getting better at using docker will allow programmers to more easily maintain and scale their projects in production.

### Sources
* [Docker Docs](https://docs.docker.com/)