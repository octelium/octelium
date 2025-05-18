import { getClientUser } from "@/utils/client";
import { useAppSelector } from "@/utils/hooks";
import * as React from "react";
import Meta from "@/components/Meta";

import {
  ListNamespaceOptions,
  ListServiceOptions,
  Namespace,
  NamespaceList,
  Service_Spec_Type,
} from "@/apis/userv1/userv1";
import { useQuery } from "@tanstack/react-query";

import {
  ResourceListItem,
  ResourceListLabel,
  ResourceListWrapper,
} from "@/components/ResourceList";
import EmptyList from "@/components/EmptyList";
import { Service, ServiceList } from "@/apis/userv1/userv1";
import { getDomain, printResourceNameWithDisplay, toNumOrZero } from "@/utils";
import Label from "@/components/Label";
import { match } from "ts-pattern";
import Paginator from "@/components/Paginator";
import { useNavigate, useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";
import InfoItem from "@/components/InfoItem";
import CopyText from "@/components/CopyText";
import { BiLinkExternal } from "react-icons/bi";

import { getServicePrivateFQDN, getServicePublicFQDN } from "@/utils/octelium";
import { Timestamp } from "@/apis/google/protobuf/timestamp";

import { GoBrowser } from "react-icons/go";
import { BiLogoPostgresql } from "react-icons/bi";
import { HiMiniCommandLine } from "react-icons/hi2";
import { TbApi } from "react-icons/tb";
import { SiKubernetes } from "react-icons/si";
import { SiMysql } from "react-icons/si";
import { MdHttp } from "react-icons/md";
import { FaGlobe } from "react-icons/fa";

import { IoIosDesktop } from "react-icons/io";
import { Button, Text } from "@mantine/core";
import { Collapse } from "@mantine/core";
import parseQuery from "@/utils/parseQuery";

const Item = (props: { item: Namespace; domain: string; skipNS?: boolean }) => {
  const { item } = props;

  const md = item.metadata!;
  const qry = useQuery({
    queryKey: ["user/main.listSvcByNamespace", item.metadata?.name],
    queryFn: async () => {
      return await getClientUser().listService(ListServiceOptions.create({
        namespace: item.metadata!.name,
      }));
    },
  });

  return (
    <div className="font-semibold w-full">
      <div className="flex items-start">
        <div className="flex flex-col flex-1">
          <div className="flex items-center font-bold">
            <Text className="mr-2 flex flex-row" size="sm" fw={"bold"}>
              <CopyText value={item.metadata!.name} />

              {md.displayName && (
                <Text className="ml-3" c="gray.7" inherit>
                  {md.displayName}
                </Text>
              )}
            </Text>
          </div>
          <div className="w-full mt-1 flex flex-row">
            {qry.isSuccess &&
              qry.data &&
              qry.data.response.listResponseMeta &&
              qry.data.response.listResponseMeta.totalCount > 0 && (
                <ResourceListLabel
                  to={`/services?namespace=${item.metadata!.name}`}
                >
                  {qry.data.response.listResponseMeta.totalCount} Services
                </ResourceListLabel>
              )}
          </div>
        </div>
      </div>
    </div>
  );
};

const NamespaceListC = (props: { itemsList: NamespaceList }) => {
  let [searchParams, _] = useSearchParams();
  const path = `/namespaces`;

  const domain = getDomain();

  return (
    <div>
      <Paginator meta={props.itemsList.listResponseMeta!} path={path} />

      <ResourceListWrapper>
        {props.itemsList.items.length === 0 && (
          <EmptyList title="No Namespaces Found"></EmptyList>
        )}
        {props.itemsList.items.map((item) => (
          <ResourceListItem key={item.metadata!.uid}>
            <Item
              item={item}
              domain={domain}
              skipNS={searchParams.has("namespace")}
            />
          </ResourceListItem>
        ))}
      </ResourceListWrapper>

      <Paginator meta={props.itemsList.listResponseMeta!} path={path} />
    </div>
  );
};

const Page = () => {
  const settings = useAppSelector((state) => state.settings);

  let [searchParams, _] = useSearchParams();

  let opts = parseQuery<{ common: { page: number; itemsPerPage?: number } }>(
    searchParams.toString()
  );
  if (opts.common && opts.common.page && opts.common.page > 0) {
    opts.common.page = opts.common.page - 1;
  }

  let o = ListNamespaceOptions.fromJsonString(JSON.stringify(opts));
  ListNamespaceOptions.mergePartial(o, {
    common: {
      itemsPerPage: settings.itemsPerPage,
    },
  });

  const qry = useQuery({
    queryKey: [
      "user/main.listNamespaces",
      ListNamespaceOptions.toJsonString(o),
    ],
    queryFn: async () => {
      return await getClientUser().listNamespace(o);
    },
  });

  return (
    <>
      <title>Namespaces - Octelium Portal</title>
      <div className="mt-4 mb-6">
        <div
          className={twMerge("font-bold text-3xl text-gray-800")}
          style={{
            textShadow: "0 2px 8px rgba(0, 0, 0, 0.2)",
          }}
        >
          Namespaces
        </div>
      </div>

      {qry.isSuccess && qry.data && (
        <NamespaceListC itemsList={qry.data.response} />
      )}
    </>
  );
};

export default Page;
