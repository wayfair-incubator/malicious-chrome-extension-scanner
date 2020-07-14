#!/bin/zsh
loggedInUser=$( stat -f "%Su" /dev/console )

path="/Users/${loggedInUser}/Library/Application Support/Google/Chrome/Default/Extensions"
if [[ $1 != "" ]]; then
  path=$1
  echo "Read extensions from \"$path\""
  echo
fi

JSONS=$( find "$path" -maxdepth 4 -name "manifest.json" )

while read JSON; do
    NAME=$( awk -F'"' '/name/{print $4}' "$JSON" )
    VERSION=$( awk -F'"' '/"version"/{print $4}' "$JSON" )
    DESCRIPTION=$( awk -F'"' '/"description"/{print $4}' "$JSON" )
    ID=$( echo "$JSON" | awk -F'/' '{print $(NF-2)}'  )
    EXT_PATH="$path/$ID"

    if [[ ! -z "$NAME" ]] && [[ ! "$NAME" =~ "_MSG_" ]]; then
        EXTS+=( "${NAME}\n" )
        echo "id: $ID"
        echo "name: $NAME"
        echo "version: $VERSION"
        echo "description: $DESCRIPTION"
        echo "path: $EXT_PATH"
        echo "url: $URL"
        echo
    fi
done < <(echo "$JSONS")