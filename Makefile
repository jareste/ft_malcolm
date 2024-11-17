NAME = ft_malcolm

#########
RM = rm -rf
CC = cc
CFLAGS = -Werror -Wextra -Wall -O3 -static
LDFLAGS = -lm
RELEASE_CFLAGS = $(CFLAGS) -DNDEBUG
#########

#########
FILES = main

SRC = $(addsuffix .c, $(FILES))

vpath %.c srcs inc 
#########

#########
OBJ_DIR = objs
OBJ = $(addprefix $(OBJ_DIR)/, $(SRC:.c=.o))
DEP = $(addsuffix .d, $(basename $(OBJ)))
#########

#########
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(@D)
	${CC} -MMD $(CFLAGS) -c -Iinc $< -o $@

all: .gitignore
	$(MAKE) $(NAME)

$(NAME): $(OBJ) Makefile
	$(CC) $(CFLAGS) $(OBJ) -o $(NAME) $(LDFLAGS)
	@echo "EVERYTHING DONE  "
#	@./.add_path.sh

release: CFLAGS = $(RELEASE_CFLAGS)
release: re
	@echo "RELEASE BUILD DONE  "

clean:
	$(RM) $(OBJ) $(DEP)
	$(RM) -r $(OBJ_DIR)
	@echo "OBJECTS REMOVED   "

.gitignore:
	@if [ ! -f .gitignore ]; then \
		echo ".gitignore not found, creating it..."; \
		echo ".gitignore" >> .gitignore; \
		echo "$(NAME)" >> .gitignore; \
		echo "$(OBJ_DIR)/" >> .gitignore; \
		echo ".gitignore created and updated with entries."; \
	else \
		echo ".gitignore already exists."; \
	fi


fclean: clean
	$(RM) $(NAME)
	@echo "EVERYTHING REMOVED   "

re:	fclean all

test:
			docker compose -f test/docker-compose.yml up -d

test_stop:
			docker compose -f test/docker-compose.yml down

.PHONY: all clean fclean re release .gitignore test test_stop

-include $(DEP)