!/bin/bash

# Function to check if the file/device exists
check_file() {
    if [ ! -e "$1" ]; then
        echo "Error: $1 does not exist."
        exit 1
    fi
}

# Function to unmount the device if it's mounted
unmount_device() {
    mountpoints=$(lsblk -o MOUNTPOINT -n "$1" | grep -v '^$')
    if [ -n "$mountpoints" ]; then
        echo "Unmounting $1..."
        sudo umount "$1"*
        if [ $? -ne 0 ]; then
            echo "Error: Failed to unmount $1."
            exit 1
        fi
    fi
}

# Prompt for firmware file
read -p "Enter the firmware file path: " firmware_file
check_file "$firmware_file"

# Prompt for device file
read -p "Enter the device file (e.g., /dev/sdb): " device_file
check_file "$device_file"

# Unmount the device before writing
unmount_device "$device_file"

# Confirm before proceeding
read -p "This will overwrite the device $device_file. Are you sure? (y/N): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "Operation canceled."
    exit 1
fi

# Write the firmware to the device using dd
echo "Writing firmware to $device_file..."
sudo dd if="$firmware_file" of="$device_file" bs=512 status=progress
if [ $? -eq 0 ]; then
    echo "Firmware successfully written to $device_file."
else
    echo "Error: Failed to write firmware to $device_file."
    exit 1
fi

# Sync to ensure all data is written
echo "Syncing data to $device_file..."
sync

# Completion message
echo "Operation completed successfully."

