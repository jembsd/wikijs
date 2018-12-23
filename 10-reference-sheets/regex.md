<!-- TITLE: Regex -->
<!-- SUBTITLE: List of useful regular expressions -->

# Regex Table
# Search & Replace
## Prepend text to a line
### Find all lines begining with a capital letter and ending with ":" then prepend two hashes "##".

```
S: ^["A-Z"].*:
R: ## $&
```