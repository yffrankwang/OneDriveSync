 OneDriveSync
=============

One Drive Synchronize Command Line Tool.


 INSTALLATION
---------------

Install dependencies

    pip install --upgrade pytz tzlocal python-dateutil onedrivesdk exifread 

On Windows, download and install [pwin32](https://sourceforge.net/projects/pywin32/).

Using git to get source

    git clone https://github.com/pandafw/OneDriveSync.git
    
Configure options for file synchronization:

    mkdir ~/the_root_dir_of_onedrive
    cp OneDriveSync.ini ~/the_root_dir_of_onedrive/.onedrivesync.ini
    # modify options
    

 RUN
-----

    cd ~/the_root_dir_of_onedrive
    python OneDriveSync.py sync


 USAGE
-------

    OneDriveSync.py <command> ...
      <command>:
        help                print command usage
        get <id>            print remote file info
        tree                list remote folders
        list [all]          list [all] remote files
        scan                scan local files
        pull [go] [force]   download remote files
          [force]           force to update file whose size is different
                            force to trash file that not exists in remote
          [go]              no confirm (always yes)
        push [go] [force]   upload local files
          [force]           force to update file whose size is different
                            force to trash file that not exists in local
        sync [go]           synchronize local <--> remote files
        touch [go]          set local file's modified date by remote
        patch [go]          set remote file's modified date by local
        drop                delete all remote files


 RUNTIME FILES
--------------------
A token file is created during execution:

* `.onedrivesync.token`: which has the token to authenticate to One Drive
