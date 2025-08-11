FROM ubuntu:20.04

RUN apt-get update && apt-get install -y socat && apt-get clean && useradd user && mkdir /app
ADD share/glibc/libc-2.31.so /usr/lib/x86_64-linux-gnu/libc-2.31.so
ADD share/glibc/ld-2.31.so /usr/lib/x86_64-linux-gnu/ld-2.31.so
ADD share/bof7 /app
ADD share/flag.txt /app
ADD share/run.sh /app

RUN chmod +x /usr/lib/x86_64-linux-gnu/libc-2.31.so /usr/lib/x86_64-linux-gnu/ld-2.31.so /app/bof7 /app/run.sh && \
	chmod 444 /app/flag.txt

WORKDIR /app
EXPOSE 9993
CMD ["/app/run.sh"]
