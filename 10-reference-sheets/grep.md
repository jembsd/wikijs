<!-- TITLE: Grep/Awk/Sed/Vim -->
<!-- SUBTITLE: A quick summary of Grep -->

# Grep

# Awk

# Sed

### Delete all lines between tags including tags:

    sed '/<tag>/,/<\/tag>/d' input.txt

> Useful when you are accessing the webpage using curl and their LFI and you want to remove the html/ body tags.
