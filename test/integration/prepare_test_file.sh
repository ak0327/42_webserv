#!/bin/bash

ROOTDIR=html

GRAY="\033[90m"
RESET="\033[0m"

create_permission_files() {
  clear_permission_files

  local workdir
  workdir="$ROOTDIR/permission"
  echo -e "${GRAY}create permission files : $workdir${RESET}"

  mkdir "$workdir"

  declare -a names=("___" "__x" "_w_" "r__" "rwx")

  for name in "${names[@]}"; do
    mkdir "$workdir/$name"

    for file in "${names[@]}"; do
      echo -e "$file.html in $name" > "$workdir/$name/$file.html"
    done

    chmod 000 $workdir/$name/*.html
    chmod +r $workdir/$name/*r*.html
    chmod +w $workdir/$name/*w*.html
    chmod +x $workdir/$name/*x*.html
#    ls -l "$workdir/$name/"
  done


  for file in "${names[@]}"; do
    echo "$file.html in $name" > "$workdir/$file.html"
  done

  chmod 000 $workdir/*
  chmod +r $workdir/*r*
  chmod +w $workdir/*w*
  chmod +x $workdir/*x*
#  ls -l "$workdir/"
  echo -e "${GRAY}created${RESET}"
}


create_big_size_files() {
  local workdir
  workdir="$ROOTDIR/big_size"
  rm -rf $workdir > /dev/null

  echo -e "${GRAY}create big size files : $workdir${RESET}"

  mkdir "$workdir"

  echo `python3 -c "print('01234567' * 128)"` > "$workdir/1kB.txt"
  echo `python3 -c "print('01234567' * 128 * 10)"` > "$workdir/10kB.txt"
  echo `python3 -c "print('01234567' * 128 * 50)"` > "$workdir/50kB.txt"
  echo `python3 -c "print('01234567' * 128 * 60)"` > "$workdir/60kB.txt"
  echo `python3 -c "print('01234567' * 128 * 70)"` > "$workdir/70kB.txt"
  echo `python3 -c "print('01234567' * 128 * 100)"` > "$workdir/100kB.txt"
  echo `python3 -c "print('01234567' * 128 * 1024)"` > "$workdir/1MB.txt"
  echo `python3 -c "print('01234567' * 128 * 1024 * 10)"` > "$workdir/10MB.txt"
  echo `python3 -c "print('01234567' * 128 * 1024 * 19)"` > "$workdir/19MB.txt"
  echo `python3 -c "print('01234567' * 128 * 1024 * 20)"` > "$workdir/20MB.txt"
#  echo `python3 -c "print('a' * 1024 * 1024 * 100)"` > "$workdir/100MB.txt"

  ls -l "$workdir"
  echo -e "${GRAY}created${RESET}"
}


clear_permission_files() {
  local workdir
  workdir="$ROOTDIR/permission"
  echo -e "${GRAY}clear permission files : $workdir${RESET}"

  if [[ -d $workdir ]]; then
    chmod -R 777 $workdir
    rm -rf $workdir
  fi
  echo -e "${GRAY}clear finish${RESET}"
}


clear_big_size_files() {
  local workdir
  workdir="$ROOTDIR/big_size"
  echo -e "${GRAY}clear big size files : $workdir${RESET}"

  if [[ -d $workdir ]]; then
    rm -rf $workdir
  fi
  echo -e "${GRAY}clear finish${RESET}"
}


prepare_test_file() {
  create_permission_files
  create_big_size_files
}


clear_test_file() {
  clear_permission_files
  clear_big_size_files
}
