import fs from 'fs';

function updateLog(text, chatFile) {
    console.log(`Saving to file: ${text}`);
    text += '\n';

    fs.appendFile(chatFile, text, (err) => {
        if(err) {
            throw err;
        }
        else{
            console.log('200');
        }
    });

    // Add in ability to put text on the next line
    console.log("Successfully Saved Chat");
};

export default updateLog;