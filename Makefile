# 定義編譯器和選項
CC = gcc

LDFLAGS = -lpcap

# 定義目標程式名稱
TARGET = ipscanner

# 定義源文件
SRCS = main.c fill_packet.c pcap.c

# 預設目標
all: $(TARGET)

# 生成執行檔
$(TARGET):
	$(CC) -o $(TARGET) $(SRCS) $(CFLAGS) $(LDFLAGS)

# 清理執行檔
clean:
	rm -f $(TARGET)

