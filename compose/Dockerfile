FROM ubuntu:18.04

USER root

# ensure local python is preferred over distribution python
ENV PATH /usr/local/bin:$PATH
ENV PYTHONUNBUFFERED 1
ENV DEBIAN_FRONTEND noninteractive
ENV LANG C.UTF-8

########### OS Components ##########
RUN apt-get clean \
    && apt-get update \
    && apt-get -y install apt-utils \
    && apt-get -y install sudo

RUN apt-get update \
    && apt-get -y install make \
    && apt-get -y install build-essential \
    && apt-get -y install libssl-dev \
    && apt-get -y install zlib1g-dev \
    && apt-get -y install libbz2-dev \
    && apt-get -y install libreadline-dev \
    && apt-get -y install libsqlite3-dev \
    && apt-get -y install llvm \
    && apt-get -y install libncurses5-dev \
    && apt-get -y install libncursesw5-dev \
    && apt-get -y install liblzma-dev \
    && apt-get -y install liblzo2-dev \
    && apt-get -y install xz-utils \
    && apt-get -y install tk-dev \
    && apt-get -y install curl \
    && apt-get -y install wget \
    && apt-get -y install nano \
    && apt-get -y install vim \
    && apt-get install locales \
    && apt-get install unzip zip \
    && apt-get install unrar rar \
    && apt-get -y install p7zip-full \
    && apt-get -y install git \
    && apt-get -y install clang-6.0 \
    && git config --global user.email "docker@scantist.com" \
    && git config --global user.name "scantist" \
    && echo "en_US.UTF-8 UTF-8" > /etc/locale.gen \
    && locale-gen \
    && apt-get -y install libimage-exiftool-perl \
    && apt-get -y install subversion

########## begin code clone #########
#RUN apt-get update \
#    && apt-get -y install clang-6.0
# moved to above
RUN ln -sf /usr/lib/x86_64-linux-gnu/libclang-6.0.so.1 /usr/lib/x86_64-linux-gnu/libclang-6.0.so

########### end code clone ##########

# install python3 after binwalk to avoid python3.6 installation
RUN wget --quiet https://www.python.org/ftp/python/3.8.2/Python-3.8.2.tgz \
    && tar xvf Python-3.8.2.tgz  \
    && cd Python-3.8.2 \
    && ./configure --enable-optimizations --with-ensurepip=install \
    && make -j 8 \
    && sudo make altinstall

# link python 3.8.2 to python3
# python cmd will call 2.7 directly for binwalk
RUN ln -sf /usr/local/bin/python3.8 /usr/bin/python3 \
    && ln -sf /usr/local/bin/pip3.8 /usr/bin/pip3

RUN pip3 install --upgrade pip \
    && pip3 install --upgrade cython \
    && pip3 install --upgrade wheel

############ 3rd Party Tools ##########

########### JDK 8 ##########
RUN apt-get update && apt-get install -y openjdk-8-jdk openjdk-8-jre
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64
ENV PATH $JAVA_HOME/bin:$PATH



##################### download sonarqube cli
RUN mkdir -p /usr/local/sonar-scanner-cli && \
    wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-4.7.0.2747-linux.zip -O sonarcli.zip && \
    unzip sonarcli.zip -d /usr/local/sonar-scanner-cli && \
    rm sonarcli.zip
ENV SONAR_RUNNER_HOME /usr/local/sonar-scanner-cli/sonar-scanner-4.7.0.2747-linux
ENV PATH $SONAR_RUNNER_HOME/bin:$PATH

# install njsscan
COPY ./requirements /requirements
RUN pip3 install -r /requirements/requirements.txt


# copy test project here in dockerfile
# or mounting test projects to dedicated folder path in the docker-compose.yml file

# copy proejct files inside the image so no need to use volume mapping
COPY . /app

WORKDIR /app