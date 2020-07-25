#!/bin/sh

#  fw_gen.sh
#  itlwm
#
#  Created by qcwap on 2020/3/10.
#  Copyright © 2020 钟先耀. All rights reserved.
target_file="${PROJECT_DIR}/include/FwBinary.cpp"
while [ $# -gt 0 ];
do
    case $1 in
    -P) fw_files=$2
    shift
    ;;
    
    esac
    shift
done

echo "//  itlwm\n\n//  Copyright © 2020 钟先耀. All rights reserved." >$target_file
echo "#include \"FwData.h\"">>$target_file

for fw in $fw_files; do
    fw_file_name=`basename $fw`
    fw_var_name=${fw_file_name//./_}
    fw_var_name=${fw_var_name//-/_}
    echo "">>$target_file
    echo "const unsigned char ${fw_var_name}[] = {">>$target_file
    xxd -i <$fw >>$target_file
    echo "};">>$target_file
    echo "">>$target_file
    echo "const long int ${fw_var_name}_size = sizeof(${fw_var_name});">>$target_file
done

echo "">>$target_file

echo "const struct FwDesc fwList[] = {">>$target_file
i=0;
for fw in $fw_files; do
    fw_file_name=`basename $fw`
    fw_var_name=${fw_file_name//./_}
    fw_var_name=${fw_var_name//-/_}
    echo "{IWL_FW(\"$fw_file_name\", $fw_var_name, ${fw_var_name}_size)},">>$target_file
    let i+=1
done
echo "};">>$target_file
echo "const int fwNumber = $i;">>$target_file
