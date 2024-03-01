#!/bin/bash

ROOTDIR=html

create_permission_files() {
  clear_permission_files

  local workdir
  workdir="$ROOTDIR/permission"
  echo "create permission files : $workdir"

  mkdir "$workdir"

  declare -a names=("___" "__x" "_w_" "r__" "rwx")

  for name in "${names[@]}"; do
    mkdir "$workdir/$name"

    for file in "${names[@]}"; do
      echo "$file.html in $name" > "$workdir/$name/$file.html"
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
  echo "created"
}


create_big_size_files() {
  local workdir
  workdir="$ROOTDIR/big_size"
  rm -rf $workdir > /dev/null

  echo "create big size files : $workdir"

  mkdir "$workdir"

  echo -n `python3 -c "print('01234567' * 128)"` > "$workdir/1kB.txt"
  echo -n `python3 -c "print('01234567' * 128 * 1024)"` > "$workdir/1MB.txt"
  echo -n `python3 -c "print('01234567' * 128 * 1024 * 10)"` > "$workdir/10MB.txt"
  echo -n `python3 -c "print('01234567' * 128 * 1024 * 19)"` > "$workdir/19MB.txt"
  echo -n `python3 -c "print('01234567' * 128 * 1024 * 20)"` > "$workdir/20MB.txt"
  echo -n `python3 -c "print('a' * 1024 * 1024 * 100)"` > "$workdir/100MB.txt"

  ls -l $workdir
  echo "created"
}


clear_permission_files() {
  local workdir
  workdir="$ROOTDIR/permission"
  echo "clear permission files : $workdir"

  if [[ -d $workdir ]]; then
    chmod -R 777 $workdir
    rm -rf $workdir
  fi
  echo "clear finish"
}


clear_big_size_files() {
  local workdir
  workdir="$ROOTDIR/big_size"
  echo "clear big size files : $workdir"

  if [[ -d $workdir ]]; then
    rm -rf $workdir
  fi
  echo "clear finish"
}


prepare_test_file() {
  create_permission_files
  create_big_size_files
}


clear_test_file() {
  clear_permission_files
  clear_big_size_files
}
