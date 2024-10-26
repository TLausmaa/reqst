CC = gcc
CFLAGS = -Wall -Wextra -I/opt/homebrew/include
LDFLAGS = -L/opt/homebrew/lib
LIBS = -lssl -lcrypto 
SRC_DIR = ./src
SRC = $(SRC_DIR)/main.c 
OBJ = $(SRC:.c=.o)
TARGET = req

all: $(TARGET) cleanobjects

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) $(LIBS) -o $@ $^

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean: 
	rm -f $(OBJ) $(TARGET)

cleanobjects:
	rm -f $(OBJ)

run: $(TARGET) cleanobjects exec

exec:
	./$(TARGET) $(ARGS)
