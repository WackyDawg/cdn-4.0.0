const xml2js = require('xml2js');

stream.on('error', () => {
  const err = {
    statusCode: 404,
    message: 'File not found: ' + this.getFullUrl()
  };

  const xmlResponse = {
    error: err
  };

  const xmlBuilder = new xml2js.Builder({
    rootName: 'response'
  });

  const xmlString = xmlBuilder.buildObject(xmlResponse);

  return new Missing()
    .get({
      domain: this.domain,
      isDirectory
    })
    .then(stream => {
      this.notFound = true;
      this.lastModified = new Date();

      return resolve(stream);
    })
    .catch(e => {
      return reject(xmlString);
    });
});
