FROM php:8.1-cli

ARG UID=1000
ARG GID=1000
ARG GIT_EMAIL=${GIT_EMAIL}
ARG GIT_NAME=${GIT_NAME}

RUN apt-get -y update && \
    apt-get -y install apt-utils

RUN DEBIAN_FRONTEND=noninteractive apt-get -y install git wget

# Install PHP Zip
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        libzip-dev \
        zip && \
    docker-php-ext-install zip

# Install xDebug
RUN pecl install xdebug-3.1.5 && \
    docker-php-ext-enable xdebug
RUN echo 'xdebug.mode=debug,coverage' >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo 'xdebug.client_host='$XDEBUG_HOST >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo 'xdebug.client_port='$XDEBUG_PORT >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo 'xdebug.start_with_request=yes' >> /usr/local/etc/php/conf.d/xdebug.ini && \
    echo 'xdebug.log_level=0' >> /usr/local/etc/php/conf.d/xdebug.ini
RUN export XDEBUG_MODE=debug XDEBUG_SESSION=1

# Install Composer.
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Create Internal User.
RUN groupadd -g $GID serveruser && \
    useradd -m -d /home/serveruser -r -u $UID -g serveruser serveruser

USER serveruser

COPY php-overrides.ini /usr/local/etc/php/conf.d/php-overrides.ini

RUN git config --global user.email $GIT_EMAIL
RUN git config --global user.name $GIT_NAME

WORKDIR /project/codebase

CMD ["sleep", "infinity"]
