/*
 * 
 The MIT License (MIT)

Copyright (c) 2021 Joc-Luis

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * 
 */



using Opc.Ua;
using Opc.Ua.Client;
using OPCUaClient.Objects;
using OPCUaClient.Exceptions;
using Opc.Ua.Configuration;
using Opc.Ua.Gds;
using System.Text.RegularExpressions;

namespace OPCUaClient
{
    /// <summary>
    /// Client for OPCUA Server
    /// </summary>
    public class UaClient
    {
        #region Private Fields
        private EndpointDescription EndpointDescription;
        private EndpointConfiguration EndpointConfig;
        private ConfiguredEndpoint Endpoint;
        private Session Session = null;
        private UserIdentity UserIdentity;
        private ApplicationConfiguration AppConfig;
        private int ReconnectPeriod = 10000;
        private object Lock = new object();
        private SessionReconnectHandler ReconnectHandler;
        #endregion

        #region Private methods
        private void KeepAlive(Session session, KeepAliveEventArgs e)
        {
            try
            {
                if (ServiceResult.IsBad(e.Status))
                {
                    lock (this.Lock)
                    {
                        if (this.ReconnectHandler == null)
                        {
                            this.ReconnectHandler = new SessionReconnectHandler(true);
                            this.ReconnectHandler.BeginReconnect(this.Session, this.ReconnectPeriod, this.Reconnect);
                        }
                    }
                }
            }
            catch (Exception ex)
            {


            }
        }

        private void Reconnect(object sender, EventArgs e)
        {
            if (!Object.ReferenceEquals(sender, this.ReconnectHandler))
            {
                return;
            }

            lock (this.Lock)
            {
                if (this.ReconnectHandler.Session != null)
                {
                    this.Session = (Session)this.ReconnectHandler.Session;
                }
                this.ReconnectHandler.Dispose();
                this.ReconnectHandler = null;
            }
        }

        private Subscription Subscription(int miliseconds)
        {

            var subscription = new Subscription()
            {
                PublishingEnabled = true,
                PublishingInterval = miliseconds,
                Priority = 1,
                KeepAliveCount = 10,
                LifetimeCount = 20,
                MaxNotificationsPerPublish = 1000
            };

            return subscription;

        }
        #endregion

        #region Public fields
        /// <summary>
        /// Indicates if the instance is connected to the server.
        /// </summary>
        public bool IsConnected
        {
            get
            {
                if (this.Session == null)
                {
                    return false;
                }
                return this.Session.Connected;
            }
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Create a new instance
        /// </summary>
        /// <param name="appName">
        /// Name of the application
        /// </param>
        /// <param name="serverUrl">
        /// Url of server
        /// </param>
        /// <param name="security">
        /// Enable or disable the security
        /// </param>
        /// <param name="untrusted">
        /// Accept untrusted certificates
        /// </param>
        /// <param name="user">
        /// User of the OPC UA Server
        /// </param>
        /// <param name="password">
        /// Password of the user
        /// </param>
        public UaClient(String appName, String serverUrl, bool security, bool untrusted, String user = "", String password = "")
        {
            String path = Path.Combine(Directory.GetCurrentDirectory(), "Certificates");
            Directory.CreateDirectory(path);
            Directory.CreateDirectory(Path.Combine(path, "Application"));
            Directory.CreateDirectory(Path.Combine(path, "Trusted"));
            Directory.CreateDirectory(Path.Combine(path, "TrustedPeer"));
            Directory.CreateDirectory(Path.Combine(path, "Rejected"));
            String hostName = System.Net.Dns.GetHostName();

            if (user.Length > 0)
            {
                UserIdentity = new UserIdentity(user, password);
            }
            else
            {
                UserIdentity = new UserIdentity();
            }
            Console.WriteLine($"Application URI: {Utils.Format(@"urn:{0}" + appName, hostName)}");
            AppConfig = new ApplicationConfiguration
            {
                ApplicationName = appName,
                ApplicationUri = Utils.Format(@"urn:{0}" + appName, hostName),
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreLocation = @"Directory",
                        StorePath = Path.Combine(path, "Application"),
                        SubjectName = $"CN={appName}, DC={hostName}"
                    },
                    TrustedIssuerCertificates = new CertificateTrustList
                    {
                        StoreType = @"Directory",
                        StorePath = Path.Combine(path, "Trusted")
                    },
                    TrustedPeerCertificates = new CertificateTrustList
                    {
                        StoreType = @"Directory",
                        StorePath = Path.Combine(path, "TrustedPeer")
                    },
                    RejectedCertificateStore = new CertificateTrustList
                    {
                        StoreType = @"Directory",
                        StorePath = Path.Combine(path, "Rejected")
                    },
                    AutoAcceptUntrustedCertificates = true,
                    AddAppCertToTrustedStore = true,
                    RejectSHA1SignedCertificates = false
                },
                TransportConfigurations = new TransportConfigurationCollection(),
                TransportQuotas = new TransportQuotas { OperationTimeout = 20000 },
                ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 5000 },
                TraceConfiguration = new TraceConfiguration
                {
                    DeleteOnLoad = true,
                },
                DisableHiResClock = false
            };
            AppConfig.Validate(ApplicationType.Client).GetAwaiter().GetResult();

            if (AppConfig.SecurityConfiguration.AutoAcceptUntrustedCertificates)
            {
                AppConfig.CertificateValidator.CertificateValidation += (s, ee) =>
                {
                    ee.Accept = (ee.Error.StatusCode == StatusCodes.BadCertificateUntrusted && untrusted);
                };
            }

            var application = new ApplicationInstance
            {
                ApplicationName = appName,
                ApplicationType = ApplicationType.Client,
                ApplicationConfiguration = AppConfig
            };
            Utils.SetTraceMask(0);
            application.CheckApplicationInstanceCertificate(true, 2048).GetAwaiter().GetResult();

            EndpointDescription = CoreClientUtils.SelectEndpoint(AppConfig, serverUrl, security);
            EndpointConfig = EndpointConfiguration.Create(AppConfig);
            Endpoint = new ConfiguredEndpoint(null, EndpointDescription, EndpointConfig);

        }

        /// <summary>
        /// Open the connection with the OPC UA Server
        /// </summary>
        /// <param name="timeOut">
        /// Timeout to try to connect with the server in seconds.
        /// </param>
        /// <param name="keepAlive">
        /// Sets whether to try to connect to the server in case the connection is lost.
        /// </param>
        /// <exception cref="ServerException"></exception>

        public void Connect(uint timeOut = 5, bool keepAlive = false)
        {
            this.Disconnect();

            this.Session = Task.Run(async () => await Session.Create(AppConfig, Endpoint, false, false, AppConfig.ApplicationName, timeOut * 1000, UserIdentity, null)).GetAwaiter().GetResult();

            if (keepAlive)
            {
                this.Session.KeepAlive += (session, e) => KeepAlive((Session)session, e);
            }

            if (this.Session == null || !this.Session.Connected)
            {
                throw new ServerException("Error creating a session on the server");
            }
        }

        /// <summary>
        /// Close the connection with the OPC UA Server
        /// </summary>
        public void Disconnect()
        {
            if (this.Session != null && this.Session.Connected)
            {

                if (this.Session.Subscriptions != null && this.Session.Subscriptions.Any())
                {
                    foreach (var subscription in this.Session.Subscriptions)
                    {
                        subscription.Delete(true);
                    }
                }
                this.Session.Close();
                this.Session.Dispose();
                this.Session = null;
            }
        }


        /// <summary>
        /// Write a value on a tag
        /// </summary>
        /// <param name="address">
        /// Address of the tag
        /// </param>
        /// <param name="value">
        /// Value to write
        /// </param>
        /// <exception cref="WriteException"></exception>
        public void Write(String address, Object value)
        {

            WriteValueCollection writeValues = new WriteValueCollection();
            var writeValue = new WriteValue
            {
                NodeId = new NodeId(address, 2),
                AttributeId = Attributes.Value,
                Value = new DataValue()
            };
            writeValue.Value.Value = value;
            writeValues.Add(writeValue);
            this.Session.Write(null, writeValues, out StatusCodeCollection statusCodes, out DiagnosticInfoCollection diagnosticInfo);
            if (!StatusCode.IsGood(statusCodes[0]))
            {
                throw new WriteException("Error writing value. Code: " + statusCodes[0].Code.ToString());
            }
        }



        /// <summary>
        /// Write a value on a tag
        /// </summary>
        /// <param name="tag"> <see cref="Tag"/></param>
        /// <exception cref="WriteException"></exception>
        public void Write(Tag tag)
        {
            this.Write(tag.Address, tag.Value);
        }


        /// <summary>
        /// Read a tag of the sepecific address
        /// </summary>
        /// <param name="address">
        /// Address of the tag
        /// </param>
        /// <returns>
        /// <see cref="Tag"/>
        /// </returns>
        public Tag Read(String address, ushort nameSpace = 2)
        {
            var tag = new Tag
            {
                Address = address,
                Value = null,
            };
            ReadValueIdCollection readValues = new ReadValueIdCollection()
            {
                new ReadValueId
                {
                    NodeId = new NodeId(address, nameSpace),
                    AttributeId = Attributes.Value
                }
            };

            this.Session.Read(null, 0, TimestampsToReturn.Both, readValues, out DataValueCollection dataValues, out DiagnosticInfoCollection diagnosticInfo);
            tag.Value = dataValues[0].Value;
            tag.Code = dataValues[0].StatusCode;

            return tag;

        }



        /// <summary>
        /// Write a lis of values
        /// </summary>
        /// <param name="tags"> <see cref="Tag"/></param>
        /// <exception cref="WriteException"></exception>
        public void Write(List<Tag> tags)
        {
            WriteValueCollection writeValues = new WriteValueCollection();



            writeValues.AddRange(tags.Select(tag => new WriteValue
            {
                NodeId = new NodeId(tag.Address, 2),
                AttributeId = Attributes.Value,
                Value = new DataValue()
                {
                    Value = tag.Value
                }
            }));

            this.Session.Write(null, writeValues, out StatusCodeCollection statusCodes, out DiagnosticInfoCollection diagnosticInfo);

            if (statusCodes.Where(sc => !StatusCode.IsGood(sc)).Any())
            {
                var status = statusCodes.Where(sc => !StatusCode.IsGood(sc)).First();
                throw new WriteException("Error writing value. Code: " + status.Code.ToString());
            }
        }



        /// <summary>
        /// Read a list of tags on the OPCUA Server
        /// </summary>
        /// <param name="address">
        /// List of address to read.
        /// </param>
        /// <returns>
        /// A list of tags <see cref="Tag"/>
        /// </returns>
        public List<Tag> Read(List<String> address)
        {
            var tags = new List<Tag>();
            int i = 0;

            ReadValueIdCollection readValues = new ReadValueIdCollection();
            readValues.AddRange(address.Select(a => new ReadValueId
            {
                NodeId = new NodeId(a, 2),
                AttributeId = Attributes.Value
            }));

            this.Session.Read(null, 0, TimestampsToReturn.Both, readValues, out DataValueCollection dataValues, out DiagnosticInfoCollection diagnosticInfo);

            address.ForEach(a =>
            {
                tags.Add(new Tag
                {
                    Address = a,
                    Value = dataValues[i].Value,
                    Code = dataValues[i].StatusCode
                });
                i++;
            });

            return tags;
        }

        /// <summary>
        /// Monitoring a tag and execute a function when the value change
        /// </summary>
        /// <param name="address">
        /// Address of the tag
        /// </param>
        /// <param name="miliseconds">
        /// Sets the time to check changes in the tag
        /// </param>
        /// <param name="monitor">
        /// Function to execute when the value changes.
        /// </param>
        public void Monitoring(String address, int miliseconds, MonitoredItemNotificationEventHandler monitor)
        {
            var subscription = this.Subscription(miliseconds);
            MonitoredItem monitored = new MonitoredItem();
            monitored.StartNodeId = new NodeId(address, 2);
            monitored.AttributeId = Attributes.Value;
            monitored.Notification += monitor;
            subscription.AddItem(monitored);
            this.Session.AddSubscription(subscription);
            subscription.Create();
            subscription.ApplyChanges();
        }


        /// <summary>
        /// Scan root folder of OPC UA server and get all devices
        /// </summary>
        /// <param name="recursive">
        /// Indicates whether to search within device groups
        /// </param>
        /// <returns>
        /// List of <see cref="Device"/>
        /// </returns>
        public List<Device> Devices(bool recursive = false, ushort nameSpace = 2)
        {
            Browser browser = new Browser(this.Session);
            browser.BrowseDirection = BrowseDirection.Forward;
            browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
            browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

            ReferenceDescriptionCollection browseResults = browser.Browse(Opc.Ua.ObjectIds.ObjectsFolder);

            var devices = browseResults.Where(d => d.ToString() != "Server").Select(b => new Device
            {
                Address = b.ToString()
            }).ToList();

            devices.ForEach(d =>
            {
                d.Groups = this.Groups(d.Address, recursive);
                d.Tags = this.Tags(d.Address, nameSpace);
            });

            return devices;
        }


        /// <summary>
        /// Scan an address and retrieve the tags and groups
        /// </summary>
        /// <param name="address">
        /// Address to search
        /// </param>
        /// <param name="recursive">
        /// Indicates whether to search within group groups
        /// </param>
        /// <returns>
        /// List of <see cref="Group"/>
        /// </returns>
        public List<OPCUaClient.Objects.Group> Groups(String address, bool recursive = false, ushort nameSpace = 2)
        {
            var groups = new List<OPCUaClient.Objects.Group>();
            Browser browser = new Browser(this.Session);
            browser.BrowseDirection = BrowseDirection.Forward;
            browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
            browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

            ReferenceDescriptionCollection browseResults = browser.Browse(new NodeId(address, nameSpace));
            foreach (var result in browseResults)
            {
                if (result.NodeClass == NodeClass.Object)
                {
                    groups.Add(new OPCUaClient.Objects.Group
                    {
                        Address = address + "." + result.ToString()

                    });
                }
            }

            groups.ForEach(g =>
            {
                g.Groups = this.Groups(g.Address, recursive, nameSpace);
                g.Tags = this.Tags(g.Address, nameSpace);
            });

            return groups;
        }


        /// <summary>
        /// Scan an address and retrieve the tags.
        /// </summary>
        /// <param name="address">
        /// Address to search
        /// </param>
        /// <returns>
        /// List of <see cref="Tag"/>
        /// </returns>
        public List<Tag> Tags(String address, ushort nameSpace)
        {

            var tags = new List<Tag>();
            Browser browser = new Browser(this.Session);
            browser.BrowseDirection = BrowseDirection.Forward;
            browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
            browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

            ReferenceDescriptionCollection browseResults = browser.Browse(new NodeId(address, nameSpace));
            foreach (var result in browseResults)
            {
                if (result.NodeClass == NodeClass.Variable)
                {
                    tags.Add(new Tag
                    {
                        Address = address + "." + result.ToString()
                    });
                }
            }

            return tags;
        }





        #region Async methods

        /// <summary>
        /// Scan root folder of OPC UA server and get all devices
        /// </summary>
        /// <param name="recursive">
        /// Indicates whether to search within device groups
        /// </param>
        /// <returns>
        /// List of <see cref="Device"/>
        /// </returns>
        public Task<List<Device>> DevicesAsync(bool recursive = false, ushort nameSpace = 2)
        {
            return Task.Run(() =>
            {
                Browser browser = new Browser(this.Session);
                browser.BrowseDirection = BrowseDirection.Forward;
                browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
                browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

                ReferenceDescriptionCollection browseResults = browser.Browse(Opc.Ua.ObjectIds.ObjectsFolder);

                var devices = browseResults.Where(d => d.ToString() != "Server").Select(b => new Device
                {
                    Address = b.ToString()
                }).ToList();

                devices.ForEach(d =>
                {
                    d.Groups = this.Groups(d.Address, recursive);
                    d.Tags = this.Tags(d.Address, nameSpace);
                });
                return devices;
            });
        }
        /// <summary>
        /// Scans Logic folder of OPC UA server and get all devices
        /// </summary>
        /// <param name="recursive">
        /// Indicates whether to search within device groups
        /// </param>
        /// <returns>
        /// List of <see cref="Device"/>
        /// </returns>
        public Task<List<Device>> BrowseLogicAsync(bool recursive = false, ushort nameSpace = 2)
        {
            return Task.Run(() =>
            {
                Browser browser = new Browser(this.Session);
                browser.BrowseDirection = BrowseDirection.Forward;
                browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
                browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

                ReferenceDescriptionCollection browseResults = browser.Browse(Opc.Ua.ObjectIds.ObjectsFolder);

                var devices = browseResults.Where(d => d.ToString() == "Logic").Select(b => new Device
                {
                    Address = b.ToString()
                }).ToList();

                devices.ForEach(d =>
                {
                    d.Groups = this.Groups(d.Address, recursive);
                    d.Tags = this.Tags(d.Address, nameSpace);
                });
                return devices;
            });
        }


        /// <summary>
        /// Scan an address and retrieve the tags and groups
        /// </summary>
        /// <param name="address">
        /// Address to search
        /// </param>
        /// <param name="recursive">
        /// Indicates whether to search within group groups
        /// </param>
        /// <returns>
        /// List of <see cref="Group"/>
        /// </returns>
        public Task<List<OPCUaClient.Objects.Group>> GroupsAsync(String address, bool recursive = false, ushort nameSpace = 2)
        {
            return Task.Run(() =>
            {
                var groups = new List<OPCUaClient.Objects.Group>();
                Browser browser = new Browser(this.Session);
                browser.BrowseDirection = BrowseDirection.Forward;
                browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
                browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

                ReferenceDescriptionCollection browseResults = browser.Browse(new NodeId(address, nameSpace));
                foreach (var result in browseResults)
                {
                    if (result.NodeClass == NodeClass.Object)
                    {
                        groups.Add(new OPCUaClient.Objects.Group
                        {
                            Address = address + "." + result.ToString()
                        });
                    }
                }

                groups.ForEach(g =>
                {
                    g.Groups = this.Groups(g.Address, recursive, nameSpace);
                    g.Tags = this.Tags(g.Address, nameSpace);
                });

                return groups;
            });
        }


        /// <summary>
        /// Scan an address and retrieve the tags.
        /// </summary>
        /// <param name="address">
        /// Address to search
        /// </param>
        /// <returns>
        /// List of <see cref="Tag"/>
        /// </returns>
        public Task<List<Tag>> TagsAsync(String address, ushort nameSpace = 2)
        {
            return Task.Run(() =>
            {

                var tags = new List<Tag>();
                Browser browser = new Browser(this.Session);
                browser.BrowseDirection = BrowseDirection.Forward;
                browser.NodeClassMask = (int)NodeClass.Object | (int)NodeClass.Variable;
                browser.ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences;

                ReferenceDescriptionCollection browseResults = browser.Browse(new NodeId(address, nameSpace));
                foreach (var result in browseResults)
                {
                    if (result.NodeClass == NodeClass.Variable)
                    {
                        tags.Add(new Tag
                        {
                            Address = address + "." + result.ToString()
                        });
                    }
                }

                return tags;
            });
        }



        /// <summary>
        /// Write a value on a tag
        /// </summary>
        /// <param name="address">
        /// Address of the tag
        /// </param>
        /// <param name="value">
        /// Value to write
        /// </param>
        public async Task<Tag> WriteAsync(String address, Object value)
        {
            Tag tag;
            WriteValueCollection writeValues = new WriteValueCollection();
            var writeValue = new WriteValue
            {
                NodeId = new NodeId(address, 2),
                AttributeId = Attributes.Value,
                Value = new DataValue()
            };
            writeValue.Value.Value = value;
            writeValues.Add(writeValue);
            WriteResponse response = await this.Session.WriteAsync(null, writeValues, new CancellationToken());

            tag = new Tag()
            {
                Address = address,
                Value = value,
                Code = response.Results[0].Code
            };

            return tag;

        }



        /// <summary>
        /// Write a value on a tag
        /// </summary>
        /// <param name="tag"> <see cref="Tag"/></param>
        public async Task<Tag> WriteAsync(Tag tag)
        {
            tag = await this.WriteAsync(tag.Address, tag.Value);

            return tag;
        }

        /// <summary>
        /// Write a lis of values
        /// </summary>
        /// <param name="tags"> <see cref="Tag"/></param>
        public async Task<List<Tag>> WriteAsync(List<Tag> tags)
        {
            WriteValueCollection writeValues = new WriteValueCollection();



            writeValues.AddRange(tags.Select(tag => new WriteValue
            {
                NodeId = new NodeId(tag.Address, 2),
                AttributeId = Attributes.Value,
                Value = new DataValue()
                {
                    Value = tag.Value
                }
            }));

            WriteResponse response = await this.Session.WriteAsync(null, writeValues, new CancellationToken());

            for (int i = 0; i < response.Results.Count; i++)
            {
                tags[i].Code = response.Results[i].Code;
            }

            return tags;
        }



        /// <summary>
        /// Read a tag of the sepecific address
        /// </summary>
        /// <param name="address">
        /// Address of the tag
        /// </param>
        /// <returns>
        /// <see cref="Tag"/>
        /// </returns>
        public async Task<Tag> ReadAsync(String address, ushort nameSpace)
        {
            var tag = new Tag
            {
                Address = address,
                Value = null,
            };
            ReadValueIdCollection readValues = new ReadValueIdCollection()
            {
                new ReadValueId
                {
                    NodeId = new NodeId(address, nameSpace),
                    AttributeId = Attributes.Value
                }
            };

            var dataValues = await this.Session.ReadAsync(null, 0, TimestampsToReturn.Both, readValues, new CancellationToken());

            tag.Value = dataValues.Results[0].Value;
            tag.Code = dataValues.Results[0].StatusCode;

            return tag;
        }

        /// <summary>
        /// Read a list of tags on the OPCUA Server
        /// </summary>
        /// <param name="address">
        /// List of address to read.
        /// </param>
        /// <returns>
        /// A list of tags <see cref="Tag"/>
        /// </returns>
        public async Task<List<Tag>> ReadAsync(List<String> address, ushort nameSpace)
        {
            var tags = new List<Tag>();
            int i = 0;

            ReadValueIdCollection readValues = new ReadValueIdCollection();
            readValues.AddRange(address.Select(a => new ReadValueId
            {
                NodeId = new NodeId(a, nameSpace),
                AttributeId = Attributes.Value
            }));

            var dataValues = await this.Session.ReadAsync(null, 0, TimestampsToReturn.Both, readValues, new CancellationToken());

            address.ForEach(a =>
            {
                tags.Add(new Tag
                {
                    Address = a,
                    Value = dataValues.Results[i].Value,
                    Code = dataValues.Results[i].StatusCode
                });
                i++;
            });

            return tags;
        }


        #endregion


        #endregion
    }
}
