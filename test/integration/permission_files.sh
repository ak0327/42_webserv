#!/bin/bash

WORKDIR=html/permission/

create_permission_files() {
  echo "create permission files : $WORKDIR"

  mkdir "$WORKDIR"

  declare -a names=("___" "__x" "_w_" "r__" "rwx")

  for name in "${names[@]}"; do
    mkdir "$WORKDIR/$name"

    create_html_files names "$WORKDIR/$name"
    for file in "${names[@]}"; do
      echo "$file.html in $name" > "$WORKDIR/$name/$file.html"
    done

    chmod 000 $WORKDIR/$name/*.html
    chmod +r $WORKDIR/$name/*r*.html
    chmod +w $WORKDIR/$name/*w*.html
    chmod +x $WORKDIR/$name/*x*.html

#    ls -l "$WORKDIR/$name/"

  done

  for file in "${names[@]}"; do
    echo "$file.html in $name" > "$WORKDIR/$file.html"
  done

  chmod 000 $WORKDIR/*
  chmod +r $WORKDIR/*r*
  chmod +w $WORKDIR/*w*
  chmod +x $WORKDIR/*x*

#  ls -l "$WORKDIR/"
}


clear_permission_files() {
  echo "clear permission files : $WORKDIR"
  chmod -R 777 $WORKDIR
  rm -rf $WORKDIR
}
