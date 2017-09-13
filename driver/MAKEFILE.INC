$(OBJ_PATH)\$(O)\busenum.bmf : busenum.mof
    mofcomp -B:$@ busenum.mof
    wmimofck $@   




