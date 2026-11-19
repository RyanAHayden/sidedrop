FROM python:3.13-slim
ARG ZSIGN=v1.1.2
ARG ZSIGN_SHA256=747d0c185f1c20b176a33803e7a91df5db9bfabcac10dab3c41e6fbb75c82f45
ADD https://github.com/zhlynn/zsign/releases/download/${ZSIGN}/zsign-linux-musl-static.tar.gz /tmp/zsign.tgz
RUN echo "$ZSIGN_SHA256  /tmp/zsign.tgz" | sha256sum -c && tar xzf /tmp/zsign.tgz -C /usr/local/bin \
 && mv /usr/local/bin/zsign-musl /usr/local/bin/zsign && rm /tmp/zsign.tgz
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py icon.png *-sources.txt ./
COPY static ./static
# the commit for the version line (no .git in the image): deploy.sh and compose.yaml pass it
ARG COMMIT=
ENV SIDEDROP_COMMIT=$COMMIT
USER 568:568
EXPOSE 8080
# gthread so a few big downloads don't block page loads
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-k", "gthread", "--threads", "32", "--timeout", "900", "app:app"]
