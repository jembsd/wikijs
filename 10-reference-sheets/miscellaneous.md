<!-- TITLE: Miscellaneous -->
<!-- SUBTITLE: A quick summary of Miscellaneous -->

# Linux
### If you need to replace the PrtScr shortcut do the following:

1. Release the PrtScr binding by this command
2. `gsettings set org.gnome.settings-daemon.plugins.media-keys screenshot`
3. Go to Settings -> Devices -> Keyboard and scroll to the end. Press + and you will create custom shortcut.
4. Enter name: "flameshot", command: /usr/bin/flameshot gui.
5. Set shortcut to PrtScr (print).

That is it. Next time you push PrtScr flameshot will be launched.