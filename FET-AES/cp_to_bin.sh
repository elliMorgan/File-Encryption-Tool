#!/usr/bin/bash


copy_file(){
	local file=$1
	local outfile=$2
	echo "attempting to move $file to $outfile"
	cp $file $outfile>/dev/null 2>&1
	if [ $? -eq 0 ]; then
		echo $file" successfully moved to "$outfile
	else
		echo "failed to move "$file" to "$outfile
	fi
}

outfiles=("/sbin/FET-AES" "/bin/FET-AES" "/usr/bin/FET-AES")
for i in ${outfiles[@]}
do
	copy_file "FET-AES.py" $i
done